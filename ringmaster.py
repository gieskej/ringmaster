#!/usr/bin/env python3
"""
Ringmaster - a self-updating index of every web app running on this box.

Port discovery:
  * `ss -tlnp`   -> bare-metal listeners and the pids holding them
  * `docker ps`  -> containers and their published host ports

Route discovery (per port, because one port often serves a REST API at /
and a real UI somewhere else):
  * links and JSON url fields found in the response at /
  * Link: headers and one-hop redirects
  * /proc/<pid>/environ + cmdline    -> BASE_URL, --root-path, etc.
  * /proc/<pid>/cwd                  -> static/ public/ dist/ ui/ on disk
  * `docker inspect`                 -> env, Traefik PathPrefix labels, mount sources
  * a list of conventional UI paths   (/ui, /admin, /swagger, ...)

Every candidate is then actually fetched and classified as UI, API, or docs,
so nothing is listed on a hunch. Identical responses are collapsed.

Stdlib only. Run as root: it needs :80, process names from ss, and /proc.

  sudo python3 ringmaster.py
  RINGMASTER_PORT=8888 python3 ringmaster.py

Env knobs: RINGMASTER_PORT, RINGMASTER_TTL, RINGMASTER_TIMEOUT,
           RINGMASTER_MAX_PATHS, RINGMASTER_DEEP=0 to skip route discovery,
           RINGMASTER_PASSWORD / RINGMASTER_PASSWORD_FILE to require a login,
           RINGMASTER_SESSION_HOURS (default 12).

With no password set, the page is open to anyone who can reach the port, same
as before. Set one and every page asks for it first. It travels in the clear
over plain HTTP, so treat it as a lock on the LAN door, not a secret.
"""

import base64
import concurrent.futures
import hashlib
import hmac
import html
import http.cookies
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.1"
PROJECT_URL = "https://github.com/gieskej/ringmaster"

LISTEN_PORT = int(os.environ.get("RINGMASTER_PORT", "80"))
CACHE_TTL = float(os.environ.get("RINGMASTER_TTL", "45"))
PROBE_TIMEOUT = float(os.environ.get("RINGMASTER_TIMEOUT", "1.2"))
MAX_PATHS = int(os.environ.get("RINGMASTER_MAX_PATHS", "26"))
DEEP = os.environ.get("RINGMASTER_DEEP", "1") != "0"
MAX_WORKERS = 32


def _load_password():
    """Password from a file if given, else straight from the environment."""
    path = os.environ.get("RINGMASTER_PASSWORD_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            sys.exit(f"Can't read RINGMASTER_PASSWORD_FILE {path}: {exc}")
    return os.environ.get("RINGMASTER_PASSWORD", "").strip()


PASSWORD = _load_password()
AUTH_ON = bool(PASSWORD)
SESSION_TTL = float(os.environ.get("RINGMASTER_SESSION_HOURS", "12")) * 3600
COOKIE_NAME = "ringmaster_session"
LOCKOUT_AFTER = 5          # failed attempts from one address...
LOCKOUT_SECONDS = 60       # ...buys this long in the corner

_sessions = {}   # token -> expiry timestamp
_failures = {}   # client ip -> [count, locked_until]

# Ports that never serve a browser UI, or that dislike being poked.
SKIP_PORTS = {
    22, 23, 25, 53, 67, 68, 69, 110, 111, 123, 135, 137, 138, 139, 143, 161,
    389, 445, 465, 514, 587, 636, 993, 995, 1194, 1900, 2049, 3306, 5353,
    5432, 5672, 6379, 9418, 11211, 27017, 51820,
}

# Paths worth trying on anything that answers HTTP.
COMMON_PATHS = [
    "/ui/", "/web/", "/app/", "/admin/", "/dashboard/", "/console/",
    "/login", "/home", "/portal/", "/static/index.html",
    "/swagger/", "/swagger-ui/", "/docs", "/redoc", "/api/docs",
    "/openapi.json", "/graphql",
]

# Directory names under an app root that usually map to a served path.
UI_DIRS = [
    "ui", "web", "webui", "www", "public", "static", "dist", "build",
    "admin", "frontend", "client", "app",
]

# Env vars / flags that carry a URL prefix.
PREFIX_VARS = re.compile(
    r"^(BASE_URL|BASE_PATH|ROOT_PATH|SCRIPT_NAME|PUBLIC_URL|WEB_?ROOT|"
    r"CONTEXT_PATH|URL_BASE|PATH_PREFIX|SUBFOLDER|APP_BASE|SERVE_PATH|"
    r"[A-Z0-9_]*_BASE_URL|[A-Z0-9_]*_URL_BASE)$"
)
PREFIX_FLAGS = re.compile(
    r"--(?:root-path|base-url|url-base|path-prefix|base-path|context-path)"
    r"[=\s]+(/[^\s\"']*)"
)


def _run(cmd, timeout=8):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _clean_path(value):
    """Normalize a discovered path, or return None if it isn't usable."""
    if not value:
        return None
    value = value.strip().strip("\"'")
    if value.startswith(("http://", "https://")):
        # Only keep same-box URLs; take the path off them.
        match = re.match(r"https?://[^/]+(/.*)?$", value)
        value = (match.group(1) or "/") if match else None
        if not value:
            return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    value = value.split("#")[0]
    if len(value) > 120 or any(c in value for c in " \t<>\\"):
        return None
    if re.search(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|map|txt|xml)$", value, re.I):
        return None
    return value or "/"


# ---------------------------------------------------------- port discovery


def _split_host_port(addr):
    """'0.0.0.0:8080' / '[::]:8080' / '*:80' -> ('0.0.0.0', 8080)."""
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    if host in ("*", ""):
        host = "0.0.0.0"
    try:
        return host, int(port)
    except ValueError:
        return host, None


def listening_ports():
    """port -> {'process', 'pids', 'binds'} from `ss -tlnp`."""
    text = _run(["ss", "-tlnp"]) or _run(["ss", "-tln"])
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "LISTEN":
            continue
        host, port = _split_host_port(fields[3])
        if not port:
            continue
        entry = found.setdefault(port, {"process": None, "pids": [], "binds": set()})
        entry["binds"].add(host)
        proc = re.search(r'\(\("([^"]+)"', line)
        if proc and entry["process"] in (None, "docker-proxy"):
            entry["process"] = proc.group(1)
        for pid in re.findall(r"pid=(\d+)", line):
            if pid not in entry["pids"]:
                entry["pids"].append(pid)
    return found


def docker_containers():
    """host port -> container info from `docker ps`."""
    fmt = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}"
    mapped = {}
    for line in _run(["docker", "ps", "--format", fmt]).splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        cid, name, image, ports = parts
        for match in re.finditer(
            r"(?:(\d+\.\d+\.\d+\.\d+|\[[^\]]+\]):)(\d+)->(\d+)/tcp", ports
        ):
            bind, host_port, container_port = match.groups()
            entry = mapped.setdefault(
                int(host_port),
                {
                    "id": cid,
                    "name": name,
                    "image": image,
                    "container_port": int(container_port),
                    "binds": set(),
                },
            )
            entry["binds"].add(bind.strip("[]"))
    return mapped


# ----------------------------------------------------------------- fetching

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_RE = re.compile(r"<meta\s[^>]*>", re.I)
ATTR_RE = re.compile(r"""([\w:.-]+)\s*=\s*["']([^"']*)["']""")
# Checked in order when there's no <title>. Gradio (Stable Diffusion, most ML
# demos) sets document.title from JS and ships none, but names itself here.
META_TITLE_KEYS = ("og:title", "twitter:title", "application-name")
HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)
DOCS_MARKERS = re.compile(
    r"swagger-ui|redoc|rapidoc|openapi|graphiql|scalar-api", re.I
)


def _socket(port, use_tls):
    sock = socket.create_connection(("127.0.0.1", port), PROBE_TIMEOUT)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname="localhost")
    sock.settimeout(PROBE_TIMEOUT)
    return sock


def http_get(port, path="/", scheme="http", limit=32768):
    """One request to localhost:port. Returns a parsed dict, or None."""
    request = (
        f"GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n"
        "User-Agent: ringmaster\r\nAccept: text/html,application/json;q=0.9\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        sock = _socket(port, scheme == "https")
    except (OSError, ssl.SSLError, ValueError):
        return None
    try:
        sock.sendall(request)
        chunks, total = [], 0
        while total < limit:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    raw = b"".join(chunks)
    if not raw.startswith(b"HTTP/"):
        return None
    return parse_response(raw, scheme)


def _tidy(text):
    return re.sub(r"\s+", " ", html.unescape(text)).strip()[:70]


def page_title(body):
    """What the app calls itself: <title>, else the social meta tags."""
    found = TITLE_RE.search(body)
    if found:
        title = _tidy(found.group(1))
        if title:
            return title

    meta = {}
    for tag in META_RE.findall(body):
        attrs = {k.lower(): v for k, v in ATTR_RE.findall(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in META_TITLE_KEYS and attrs.get("content"):
            meta.setdefault(key, attrs["content"])
    for key in META_TITLE_KEYS:
        if key in meta:
            title = _tidy(meta[key])
            if title:
                return title
    return None


def parse_response(raw, scheme):
    """Split a raw HTTP response into status, headers, title and body."""
    head, _, body_bytes = raw.partition(b"\r\n\r\n")
    head_text = head.decode("utf-8", "replace")
    body = body_bytes.decode("utf-8", "replace")

    status = 0
    match = re.match(r"HTTP/[\d.]+\s+(\d{3})", head_text)
    if match:
        status = int(match.group(1))

    headers = {}
    for line in head_text.splitlines()[1:]:
        key, _, value = line.partition(":")
        if value:
            headers[key.strip().lower()] = value.strip()

    return {
        "scheme": scheme,
        "status": status,
        "headers": headers,
        "ctype": headers.get("content-type", "").split(";")[0].strip().lower(),
        "location": headers.get("location"),
        "title": page_title(body),
        "body": body,
        "signature": hashlib.md5(
            re.sub(r"\s+", " ", body[:4096]).encode("utf-8", "replace")
        ).hexdigest(),
    }


def probe_root(port):
    """Determine whether a port speaks HTTP or HTTPS, and grab its root."""
    result = http_get(port, "/", "http")
    if result:
        plain_tls_hint = result["status"] == 400 and re.search(
            r"(plain HTTP|to an? (SSL|HTTPS))", result["body"][:2048], re.I
        )
        if not plain_tls_hint:
            return result
    return http_get(port, "/", "https")


def classify(result):
    """'ui', 'api', 'docs', or None if this route isn't worth listing."""
    if not result or result["status"] in (0, 404, 405, 410, 501, 502, 503):
        return None
    ctype, body = result["ctype"], result["body"]
    if DOCS_MARKERS.search(body[:4096]) or "openapi" in body[:400].lower():
        return "docs"
    if ctype.startswith("text/html") or (not ctype and "<html" in body[:400].lower()):
        return "ui"
    if ctype.endswith(("json", "xml")) or body[:1].strip() in ("{", "["):
        return "api"
    if result["status"] in (401, 403) or result["location"]:
        return "ui"
    return None


# ------------------------------------------------------------ path hunting


def _paths_in_json(body):
    """Walk a JSON body for strings that look like paths worth fetching."""
    try:
        data = json.loads(body[:65536])
    except ValueError:
        return []
    found, stack, seen = [], [data], 0
    while stack and seen < 400:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node[:50])
        elif isinstance(node, str):
            path = _clean_path(node)
            if path and path != "/":
                found.append(path)
    return found


def hints_from_response(result):
    """Paths advertised by the app itself: links, JSON urls, Link headers."""
    hints = {}
    if not result:
        return hints

    if result["location"]:
        path = _clean_path(result["location"])
        if path:
            hints[path] = "redirect from /"

    link_header = result["headers"].get("link", "")
    for match in re.finditer(r"<([^>]+)>", link_header):
        path = _clean_path(match.group(1))
        if path:
            hints[path] = "Link header"

    if result["ctype"].startswith("text/html"):
        for href in HREF_RE.findall(result["body"][:16384]):
            path = _clean_path(href)
            if path and path != "/" and path.count("/") <= 3:
                hints.setdefault(path, "linked from /")

    if result["ctype"].endswith("json"):
        for path in _paths_in_json(result["body"]):
            hints.setdefault(path, "url in the API response at /")
    return hints


def hints_from_process(pids):
    """Look at what the process is: its env, its flags, its working directory."""
    hints = {}
    for pid in pids[:4]:
        base = f"/proc/{pid}"

        try:
            with open(f"{base}/environ", "rb") as handle:
                env_raw = handle.read(65536).decode("utf-8", "replace")
        except OSError:
            env_raw = ""
        for item in env_raw.split("\0"):
            key, _, value = item.partition("=")
            if PREFIX_VARS.match(key.strip()):
                path = _clean_path(value)
                if path:
                    hints.setdefault(path, f"{key} in the process environment")

        try:
            with open(f"{base}/cmdline", "rb") as handle:
                cmdline = handle.read(16384).decode("utf-8", "replace").replace("\0", " ")
        except OSError:
            cmdline = ""
        for value in PREFIX_FLAGS.findall(cmdline):
            path = _clean_path(value)
            if path:
                hints.setdefault(path, "command-line flag")

        try:
            cwd = os.path.realpath(f"{base}/cwd")
        except OSError:
            cwd = None
        if cwd and cwd not in ("/", "/proc", "/tmp") and os.path.isdir(cwd):
            hints.update(hints_from_dir(cwd))
    return hints


def hints_from_dir(root, depth=0):
    """Static UI directories on disk suggest the path they're served at."""
    hints = {}
    try:
        entries = sorted(os.listdir(root))[:200]
    except OSError:
        return hints
    for name in entries:
        full = os.path.join(root, name)
        if not os.path.isdir(full) or os.path.islink(full):
            continue
        if name.lower() in UI_DIRS:
            has_index = os.path.isfile(os.path.join(full, "index.html"))
            hints.setdefault(
                f"/{name.lower()}/",
                f"{full} on disk" + (" (has index.html)" if has_index else ""),
            )
            if has_index and depth == 0:
                # e.g. static/admin/index.html -> /static/admin/
                for sub in sorted(os.listdir(full))[:40]:
                    subfull = os.path.join(full, sub)
                    if os.path.isfile(os.path.join(subfull, "index.html")):
                        hints.setdefault(
                            f"/{name.lower()}/{sub}/", f"{subfull} on disk"
                        )
    return hints


def hints_from_container(container):
    """Env, Traefik labels and bind-mount sources from `docker inspect`."""
    hints = {}
    text = _run(["docker", "inspect", container["id"]])
    try:
        data = json.loads(text)[0]
    except (ValueError, IndexError, KeyError):
        return hints

    config = data.get("Config", {})
    for item in config.get("Env") or []:
        key, _, value = item.partition("=")
        if PREFIX_VARS.match(key.strip()):
            path = _clean_path(value)
            if path:
                hints.setdefault(path, f"{key} in the container environment")

    for key, value in (config.get("Labels") or {}).items():
        for match in re.finditer(r"PathPrefix\(`([^`]+)`\)", value or ""):
            path = _clean_path(match.group(1))
            if path:
                hints.setdefault(path, f"{key.split('.')[0]} label")
        if key.lower().endswith(("path", "base", "webroot")):
            path = _clean_path(value)
            if path:
                hints.setdefault(path, f"{key} label")

    for mount in data.get("Mounts") or []:
        source = mount.get("Source") or ""
        if source.startswith("/") and os.path.isdir(source) and "docker/volumes" not in source:
            hints.update(hints_from_dir(source, depth=1))
    return hints


# ------------------------------------------------------------------ routing


def discover_routes(port, root, scheme, host_entry, container):
    """Probe every hinted path and return the ones that really answer."""
    hints = {"/": "the port itself"}
    if DEEP:
        hints.update(hints_from_response(root))
        hints.update(hints_from_process(host_entry.get("pids", [])))
        if container:
            hints.update(hints_from_container(container))
        for path in COMMON_PATHS:
            hints.setdefault(path, "common path")

    ordered = ["/"] + [p for p in hints if p != "/"][: MAX_PATHS - 1]

    def check(path):
        return path, (root if path == "/" else http_get(port, path, scheme))

    routes, seen_signatures = [], {}
    with concurrent.futures.ThreadPoolExecutor(min(MAX_WORKERS, len(ordered))) as pool:
        for path, result in pool.map(check, ordered):
            kind = classify(result)
            if not kind:
                continue
            # Collapse pages that are byte-identical to one already listed.
            previous = seen_signatures.get(result["signature"])
            if previous is not None:
                if len(path) < len(routes[previous]["path"]):
                    routes[previous]["path"] = path
                    routes[previous]["hint"] = hints[path]
                continue
            seen_signatures[result["signature"]] = len(routes)
            routes.append(
                {
                    "path": path,
                    "kind": kind,
                    "title": result["title"],
                    "status": result["status"],
                    "hint": hints[path],
                }
            )

    routes.sort(key=lambda r: (r["path"] != "/", len(r["path"]), r["path"]))
    return routes


def pick_primary(routes):
    """The route a human wants to click: a real UI, else whatever we have."""
    uis = [r for r in routes if r["kind"] == "ui" and r["title"]]
    if uis:
        return uis[0]
    uis = [r for r in routes if r["kind"] == "ui"]
    return uis[0] if uis else routes[0]


# ------------------------------------------------------------------- scanning


# `ss` reports a thread name, which for some runtimes isn't the program at all:
# PyTorch renames its main thread, so Stable Diffusion lands on the page as
# pt_main_thread. These are the names worth looking behind.
VAGUE_COMM = re.compile(
    r"^(pt_main_thread|MainThread|Thread-\d+|python[\d.]*|node|deno|bun|ruby|"
    r"perl|java|dotnet|uvicorn|gunicorn|waitress|sh|bash|dash|su|sudo)$", re.I
)
# Script names that say nothing - the directory they sit in says more.
VAGUE_SCRIPT = re.compile(
    r"^(launch|app|main|serve|server|run|start|webui|manage|wsgi|asgi|cli|"
    r"__main__|index)\.(py|js|mjs|cjs|ts|rb)$", re.I
)
DULL_DIRS = {"/", "/root", "/tmp", "/usr", "/usr/local", "/opt", "/srv", "/var", "/home"}


def process_name(pids, reported):
    """A name for the process behind a port, better than the thread name."""
    if reported and not VAGUE_COMM.match(reported):
        return reported

    for pid in pids[:4]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                argv = [
                    part for part in
                    handle.read(16384).decode("utf-8", "replace").split("\0") if part
                ]
        except OSError:
            argv = []

        # A real program name beats anything else - and beats the working
        # directory, which for something like a language server is just
        # whatever folder it was pointed at.
        exe = os.path.basename(argv[0]) if argv else ""
        if exe and not VAGUE_COMM.match(exe):
            return exe

        script = ""
        for part in argv[1:]:
            if not part.startswith("-") and part.lower().endswith(
                (".py", ".js", ".mjs", ".cjs", ".ts", ".rb")
            ):
                script = os.path.basename(part)
                break

        try:
            cwd = os.path.realpath(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        # realpath hands back the input for a dead pid or one we can't read,
        # which would name the app "cwd" - so insist on a real directory.
        if not cwd or cwd.startswith("/proc/") or not os.path.isdir(cwd):
            cwd = ""
        # An interpreter, then: the script names it, unless the script is
        # called launch.py or app.py, in which case the checkout directory
        # does a better job (stable-diffusion-webui).
        if script and not VAGUE_SCRIPT.match(script):
            return script
        if cwd and cwd not in DULL_DIRS and cwd != os.path.expanduser("~"):
            return os.path.basename(cwd)
        if script:
            return script

    return reported or "unknown process"


def inspect_port(port, host_entry, container):
    """Everything the page needs about one port, or None if it is not a web app."""
    root = probe_root(port)
    if not root:
        return None
    scheme = root["scheme"]
    routes = discover_routes(port, root, scheme, host_entry, container)
    if not routes:
        return None
    primary = pick_primary(routes)

    binds = set(host_entry.get("binds", set())) | set(
        container["binds"] if container else set()
    )
    public = not binds or any(
        b not in ("127.0.0.1", "::1") and not b.startswith("127.") for b in binds
    )

    return {
        "port": port,
        "scheme": scheme,
        "source": "docker" if container else "host",
        "owner": container["name"] if container else process_name(
            host_entry.get("pids", []), host_entry.get("process")
        ),
        "detail": container["image"] if container else None,
        "title": primary["title"] or (routes[0]["title"] if routes else None),
        "primary": primary,
        "routes": routes,
        "status": primary["status"],
        "public": public,
        "binds": sorted(binds),
    }


def scan():
    """Sweep every listening port in parallel and return the page payload."""
    hosts = listening_ports()
    containers = docker_containers()
    candidates = sorted((set(hosts) | set(containers)) - SKIP_PORTS - {LISTEN_PORT})

    apps = []
    with concurrent.futures.ThreadPoolExecutor(MAX_WORKERS) as pool:
        futures = {
            pool.submit(inspect_port, port, hosts.get(port, {}), containers.get(port)): port
            for port in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                app = future.result()
            except Exception:  # pylint: disable=broad-exception-caught
                # one bad port shouldn't sink the whole page
                app = None
            if app:
                apps.append(app)

    apps.sort(key=lambda a: a["port"])
    return {"apps": apps, "scanned_at": time.time(), "hostname": socket.gethostname()}


_cache = {"data": {}, "at": 0.0}


def get_scan(force=False):
    """The most recent scan, re-running it when it is stale or forced."""
    now = time.time()
    if force or not _cache["data"] or now - _cache["at"] > CACHE_TTL:
        _cache["data"] = scan()
        _cache["at"] = now
    return _cache["data"]


# -------------------------------------------------------------------- render

CSS = """
:root{
  --bg:#14181d; --panel:#1b212a; --panel-2:#212934; --rule:#2c3542;
  --ink:#e7ecf3; --muted:#8a97a7; --host:#f2a63b; --docker:#56c2d6;
  --warn:#e06c5a;
  --mono:ui-monospace,"JetBrains Mono","SFMono-Regular",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:48px 24px 72px}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;
  justify-content:space-between;padding-bottom:20px;border-bottom:1px solid var(--rule)}
h1{font:600 15px/1 var(--mono);letter-spacing:.34em;text-transform:uppercase;margin:0}
h1 span{color:var(--host)}
.brand{display:flex;align-items:center;gap:11px;margin:0 0 10px}
.mark{flex:0 0 auto;display:block;border-radius:7px;line-height:0;
  transition:opacity .15s,box-shadow .15s}
.mark svg{width:28px;height:28px;display:block}
.mark:hover{opacity:.82}
.mark:focus-visible{outline:none;box-shadow:0 0 0 2px var(--bg),0 0 0 4px var(--host)}
.ver{font:500 10px/1 var(--mono);letter-spacing:.14em;color:var(--muted);
  border:1px solid var(--rule);border-radius:999px;padding:4px 8px}
.host{font:400 13px/1.4 var(--mono);color:var(--muted)}
.rescan{font:500 12px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;
  color:var(--ink);text-decoration:none;border:1px solid var(--rule);
  border-radius:999px;padding:9px 16px;transition:border-color .15s,color .15s}
.rescan:hover,.rescan:focus-visible{border-color:var(--host);color:var(--host)}
h2{font:500 12px/1 var(--mono);letter-spacing:.22em;text-transform:uppercase;
  color:var(--muted);margin:44px 0 16px}
h2 em{font-style:normal;color:var(--rule);margin-left:10px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}
.card{background:var(--panel);border:1px solid var(--rule);border-radius:10px;
  padding:16px 18px;transition:border-color .16s,background .16s}
.card:hover{border-color:var(--jack);background:var(--panel-2)}
.card.local{opacity:.75}
.top{display:flex;gap:16px;align-items:center;text-decoration:none;color:inherit}
a.top:hover .name,a.top:focus-visible .name{color:var(--jack)}
a.top:focus-visible{outline:2px solid var(--jack);outline-offset:3px;border-radius:6px}
.jack{flex:0 0 auto;width:46px;height:46px;border-radius:50%;
  border:2px solid var(--jack);display:grid;place-items:center;color:var(--jack);
  background:radial-gradient(circle at 50% 50%,var(--bg) 42%,transparent 43%)}
.jack svg{width:22px;height:22px;display:block}
.meta{min-width:0}
.port{font:600 21px/1.1 var(--mono);letter-spacing:-.01em}
.name{font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  transition:color .16s}
.sub{font:400 12px/1.5 var(--mono);color:var(--muted);overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.routes{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 0;padding-top:12px;
  border-top:1px dashed var(--rule)}
.pill{font:500 11px/1 var(--mono);text-decoration:none;padding:6px 9px;
  border-radius:5px;border:1px solid var(--rule);color:var(--muted);
  display:inline-flex;gap:6px;align-items:center;transition:border-color .14s,color .14s}
.pill:hover,.pill:focus-visible{border-color:var(--jack);color:var(--ink)}
.pill.ui{color:var(--jack);border-color:color-mix(in srgb,var(--jack) 45%,var(--rule))}
.pill.docs{border-style:dashed}
.pill i{font-style:normal;opacity:.6;font-size:10px;letter-spacing:.06em}
.pill.dead{color:var(--muted);border-style:dotted;cursor:default}
.flag{color:var(--warn)}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
  clip:rect(0 0 0 0);white-space:nowrap;border:0}
.empty{border:1px dashed var(--rule);border-radius:10px;padding:32px;color:var(--muted);
  font-size:14px}
footer{margin-top:56px;font:400 12px/1.7 var(--mono);color:var(--muted)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

ICON_DOCKER = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="4" y="11" width="6" height="5.5" rx="1"/>'
    '<rect x="11.5" y="11" width="6" height="5.5" rx="1"/>'
    '<rect x="11.5" y="4.5" width="6" height="5.5" rx="1"/>'
    '<path d="M3 19.2c4.6 2.2 12.6 1.6 16.4-3.4"/></svg>'
)

ICON_HOST = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="7.5" y="7.5" width="9" height="9" rx="2"/>'
    '<path d="M10 3.5v4M14 3.5v4M10 16.5v4M14 16.5v4'
    'M3.5 10h4M3.5 14h4M16.5 10h4M16.5 14h4"/></svg>'
)

# Kept inline because only ringmaster.py is installed - there is no static dir.
# Same artwork as assets/ringmaster-favicon.svg in the repo; edit both together.
_MARK_BODY = (
    '<rect width="64" height="64" rx="12" fill="#A32D2D"/>\n'
    '<circle cx="32" cy="41" r="12.5" fill="none" stroke="#FAEEDA" stroke-width="5"/>\n'
    '<circle cx="42.6" cy="23" r="12.5" fill="none" stroke="#A32D2D" stroke-width="9"/>\n'
    '<circle cx="42.6" cy="23" r="12.5" fill="none" stroke="#FAC775" stroke-width="5"/>\n'
    '<circle cx="21.4" cy="23" r="12.5" fill="none" stroke="#A32D2D" stroke-width="9"/>\n'
    '<circle cx="21.4" cy="23" r="12.5" fill="none" stroke="#FAC775" stroke-width="5"/>\n'
)

# Served at /favicon.svg; standalone, so it carries its own title for screen readers.
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64"'
    ' height="64" role="img" aria-labelledby="rm-title">\n'
    '<title id="rm-title">Ringmaster</title>\n' + _MARK_BODY + "</svg>\n"
)

# Inline in the page header, beside the wordmark, linking to the project. The
# art is decorative and sized by CSS; the link carries the accessible name.
MARK_SVG = (
    f'<a class="mark" href="{PROJECT_URL}" target="_blank" rel="noopener noreferrer"'
    f' title="ringmaster v{VERSION} on GitHub" aria-label="ringmaster on GitHub">'
    f'<svg viewBox="0 0 64 64" aria-hidden="true">\n{_MARK_BODY}</svg></a>'
)

HEAD_ICON = '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'

KIND_LABEL = {"ui": "app", "api": "api", "docs": "docs"}


def pill_html(route, base_url, clickable):
    """One route pill, linked unless the app is loopback-only."""
    kind = route["kind"]
    label = html.escape(route["path"])
    tip = html.escape(f"{KIND_LABEL[kind]} · found via {route['hint']}")
    body = f'{label} <i>{KIND_LABEL[kind]}</i>'
    if route["status"] in (401, 403):
        body = f'{label} <i>locked</i>'
    if not clickable:
        return f'<span class="pill {kind} dead" title="{tip}">{body}</span>'
    href = html.escape(base_url + route["path"].lstrip("/"))
    return f'<a class="pill {kind}" href="{href}" title="{tip}">{body}</a>'


def card_html(app, base_host):
    """One card: port, name, source line and its route pills."""
    docker = app["source"] == "docker"
    accent = "var(--docker)" if docker else "var(--host)"
    icon = ICON_DOCKER if docker else ICON_HOST
    kind = "Docker container" if docker else "Host process"
    base_url = f"{app['scheme']}://{base_host}:{app['port']}/"
    label = app["title"] or app["owner"]

    bits = [html.escape(app["owner"])]
    if app["detail"]:
        bits.append(html.escape(app["detail"]))
    if app["status"] in (401, 403):
        bits.append('<span class="flag">login required</span>')
    if not app["public"]:
        bits.append('<span class="flag">127.0.0.1 only</span>')
    sub = " &middot; ".join(bits)

    top_inner = (
        f'<div class="jack" title="{kind}">{icon}'
        f'<span class="sr-only">{kind}</span></div>'
        f'<div class="meta">'
        f'<div class="port">:{app["port"]}</div>'
        f'<div class="name">{html.escape(label)}</div>'
        f'<div class="sub">{sub}</div>'
        f"</div>"
    )
    primary_url = html.escape(base_url + app["primary"]["path"].lstrip("/"))
    top = (
        f'<a class="top" href="{primary_url}">{top_inner}</a>'
        if app["public"]
        else f'<div class="top">{top_inner}</div>'
    )

    routes = ""
    if len(app["routes"]) > 1 or app["routes"][0]["path"] != "/":
        pills = "".join(
            pill_html(r, base_url, app["public"]) for r in app["routes"]
        )
        routes = f'<div class="routes">{pills}</div>'

    return f'<div class="card{"" if app["public"] else " local"}" ' \
           f'style="--jack:{accent}">{top}{routes}</div>'


def page_html(data, base_host):
    """The dashboard itself."""
    public = [a for a in data["apps"] if a["public"]]
    local = [a for a in data["apps"] if not a["public"]]
    stamp = datetime.fromtimestamp(data["scanned_at"]).strftime("%H:%M:%S")
    name = html.escape(data["hostname"])
    routes_total = sum(len(a["routes"]) for a in data["apps"])
    lock_link = '<a class="rescan" href="/logout">Lock</a>' if AUTH_ON else ""

    body = []
    if public:
        body.append(f'<h2>On the network <em>{len(public)}</em></h2><div class="grid">')
        body += [card_html(a, base_host) for a in public]
        body.append("</div>")
    if local:
        body.append(f'<h2>Bound to loopback <em>{len(local)}</em></h2><div class="grid">')
        body += [card_html(a, base_host) for a in local]
        body.append("</div>")
    if not data["apps"]:
        body.append(
            '<div class="empty">Nothing on this box answered an HTTP request. '
            "Start a service, then rescan. If services are running, check that "
            "ringmaster runs as root so <code>ss -tlnp</code> can see them.</div>"
        )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ringmaster &middot; {name}</title>{HEAD_ICON}<style>{CSS}</style>
</head><body><div class="wrap">
<header>
  <div>
    <div class="brand">{MARK_SVG}<h1>RING<span>MASTER</span></h1>
      <span class="ver">v{VERSION}</span></div>
    <div class="host">{name} &middot; {len(data['apps'])} ports &middot;
      {routes_total} routes &middot; scanned {stamp}</div>
  </div>
  <div style="display:flex;gap:8px">{lock_link}
    <a class="rescan" href="/?rescan=1">Rescan</a></div>
</header>
{''.join(body)}
<footer>Ports from ss and docker ps. Routes from process env, command lines,
app directories on disk, container labels, and links the apps themselves return -
each one fetched before it's listed. Hover a route to see where it came from.
Cached {int(CACHE_TTL)}s.</footer>
</div></body></html>"""


# ---------------------------------------------------------------------- auth


def _matches(candidate):
    return hmac.compare_digest(candidate.strip(), PASSWORD)


def new_session():
    """Mint a session token, sweeping expired ones on the way past."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    for old, expiry in list(_sessions.items()):
        if expiry < now:
            _sessions.pop(old, None)
    _sessions[token] = now + SESSION_TTL
    return token


def session_valid(token):
    """Is this token live? Expired ones are dropped as they are found."""
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if expiry < time.time():
        _sessions.pop(token, None)
        return False
    return True


def locked_out(ip):
    """Is this address in its cool-off after too many bad guesses?"""
    _, until = _failures.get(ip, (0, 0))
    return time.time() < until


def note_failure(ip):
    """Count a bad guess, and start the lockout once there are enough."""
    count, until = _failures.get(ip, (0, 0))
    count += 1
    if count >= LOCKOUT_AFTER:
        _failures[ip] = (0, time.time() + LOCKOUT_SECONDS)
    else:
        _failures[ip] = (count, until)


def note_success(ip):
    """A good password clears whatever this address had against it."""
    _failures.pop(ip, None)


LOGIN_CSS = """
.login{max-width:380px;margin:14vh auto 0}
.login .card{padding:28px 26px;border-color:var(--rule)}
.login h1{margin-bottom:6px}
.login p{font:400 13px/1.5 var(--mono);color:var(--muted);margin:0 0 22px}
.login label{display:block;font:500 11px/1 var(--mono);letter-spacing:.2em;
  text-transform:uppercase;color:var(--muted);margin-bottom:8px}
.login input{width:100%;background:var(--bg);border:1px solid var(--rule);
  border-radius:7px;color:var(--ink);font:400 15px/1 var(--mono);padding:13px 14px;
  outline:none}
.login input:focus{border-color:var(--host)}
.login button{margin-top:14px;width:100%;background:var(--host);color:#14181d;
  border:0;border-radius:7px;font:600 12px/1 var(--mono);letter-spacing:.18em;
  text-transform:uppercase;padding:14px;cursor:pointer}
.login button:hover{filter:brightness(1.08)}
.error{margin-top:14px;font:400 12px/1.5 var(--mono);color:var(--warn)}
"""


def login_html(hostname, error=None):
    """The password page, with an optional error under the form."""
    name = html.escape(hostname)
    note = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ringmaster &middot; {name}</title>{HEAD_ICON}<style>{CSS}{LOGIN_CSS}</style>
</head><body><div class="wrap login" style="--jack:var(--host)">
  <h1>RING<span>MASTER</span></h1>
  <p>{name}</p>
  <div class="card">
    <form method="post" action="/login">
      <label for="pw">Password</label>
      <input id="pw" name="password" type="password" autofocus autocomplete="current-password">
      <button type="submit">Unlock</button>
    </form>
    {note}
  </div>
</div></body></html>"""


# -------------------------------------------------------------------- server


class Handler(BaseHTTPRequestHandler):
    """The whole HTTP surface: dashboard, JSON, favicon, login, health."""

    server_version = "ringmaster"

    def _send(self, body, ctype="text/html; charset=utf-8", code=200, extra=(),
              cache="no-store"):
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", cache)
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    # -- auth plumbing ----------------------------------------------------

    @property
    def client_ip(self):
        """Who is asking - used for the per-address lockout."""
        return self.client_address[0] if self.client_address else "?"

    def _cookie_token(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
        except http.cookies.CookieError:
            return ""
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else ""

    def _basic_ok(self):
        """Lets curl and scripts hit /apps.json without a browser session."""
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(None, 1)[1]).decode("utf-8", "replace")
        except (ValueError, IndexError):
            return False
        return _matches(decoded.partition(":")[2])

    def authed(self):
        """True when no password is set, or the caller has proved they know it."""
        if not AUTH_ON:
            return True
        return session_valid(self._cookie_token()) or self._basic_ok()

    def _cookie_header(self, token, clear=False):
        parts = [
            f"{COOKIE_NAME}={'' if clear else token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0" if clear else f"Max-Age={int(SESSION_TTL)}",
        ]
        return ("Set-Cookie", "; ".join(parts))

    def _challenge(self, wants_json, error=None):
        """Ask for the password: a 401 for scripts, the login page for browsers."""
        if wants_json:
            self._send(
                json.dumps({"error": "authentication required"}),
                "application/json",
                401,
                [("WWW-Authenticate", 'Basic realm="ringmaster"')],
            )
            return
        code = 401 if error else 200
        self._send(login_html(socket.gethostname(), error), code=code)

    # -- routes -----------------------------------------------------------

    def _open_route(self, path):
        """Endpoints answered before the password check. True if handled."""
        if path == "/healthz":
            self._send("ok", "text/plain; charset=utf-8")
            return True

        # Open so the login page gets its icon too.
        if path in ("/favicon.svg", "/favicon.ico"):
            self._send(
                FAVICON_SVG, "image/svg+xml; charset=utf-8",
                cache="public, max-age=86400",
            )
            return True

        if path == "/logout":
            _sessions.pop(self._cookie_token(), None)
            self._send(
                "", "text/html; charset=utf-8", 303,
                [("Location", "/"), self._cookie_header("", clear=True)],
            )
            return True

        return False

    # do_GET/do_POST are named by BaseHTTPRequestHandler, not by us.
    def do_GET(self):  # pylint: disable=invalid-name
        """Serve the dashboard, the JSON, or one of the open endpoints."""
        path, _, query = self.path.partition("?")
        if self._open_route(path):
            return

        wants_json = path == "/apps.json"
        if not self.authed():
            self._challenge(wants_json)
            return

        if path == "/login":
            self._send("", "text/html; charset=utf-8", 303, [("Location", "/")])
            return

        data = get_scan(force="rescan" in query)

        if wants_json:
            self._send(json.dumps(data, indent=2), "application/json")
            return
        if path not in ("/", "/index.html"):
            self._send("not found", "text/plain; charset=utf-8", 404)
            return

        host_header = self.headers.get("Host", "") or data["hostname"]
        if host_header.startswith("["):
            base_host = host_header.split("]")[0] + "]"
        else:
            base_host = host_header.rsplit(":", 1)[0]
        self._send(page_html(data, base_host))

    def do_POST(self):  # pylint: disable=invalid-name
        """Only /login posts anywhere: check the password, hand out a session."""
        path, _, _query = self.path.partition("?")
        if path != "/login" or not AUTH_ON:
            self._send("not found", "text/plain; charset=utf-8", 404)
            return

        if locked_out(self.client_ip):
            self._challenge(False, "Too many attempts. Wait a minute.")
            return

        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = urllib.parse.parse_qs(body)
        candidate = (fields.get("password") or [""])[0]

        if not _matches(candidate):
            note_failure(self.client_ip)
            time.sleep(0.4)  # take the shine off brute forcing
            self._challenge(False, "Wrong password.")
            return

        note_success(self.client_ip)
        self._send(
            "", "text/html; charset=utf-8", 303,
            [("Location", "/"), self._cookie_header(new_session())],
        )

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Silence the per-request stderr logging systemd would capture."""


def main():
    """Bind the port and serve until interrupted."""
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    except PermissionError:
        sys.exit(f"Can't bind port {LISTEN_PORT}. Run with sudo, or set RINGMASTER_PORT.")
    print(
        f"ringmaster serving on http://0.0.0.0:{LISTEN_PORT} "
        f"({'password required' if AUTH_ON else 'no password set'})",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    main()
