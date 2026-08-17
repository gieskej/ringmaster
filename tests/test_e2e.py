#!/usr/bin/env python3
"""
End-to-end tests: start the real ringmaster process and talk to it over HTTP.

Nothing is mocked. Fake apps are stood up on loopback ports so the discovery
tests exercise the whole path - ss finds the port, ringmaster fetches it,
classifies what comes back, and hunts for the routes behind it.

    python3 -m unittest discover -s tests -v
    python3 tests/test_e2e.py            # same thing

Stdlib only, like the app. Tests that need `ss` skip themselves without it.
"""

import base64
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RINGMASTER = os.path.join(ROOT, "ringmaster.py")
INSTALL_SH = os.path.join(ROOT, "scripts", "install.sh")
FAVICON = os.path.join(ROOT, "assets", "ringmaster-favicon.svg")

BOOT_TIMEOUT = 20        # seconds to wait for the server to answer /healthz
SCAN_TIMEOUT = 90        # a deep scan probes every port on the box


# --------------------------------------------------------------- plumbing


def free_port():
    """A port nothing is listening on, as of a moment ago."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# An HTTP request just has this many parts; splitting them up would only hide it.
def request(  # pylint: disable=too-many-arguments
    port, path, method="GET", *, body=None, headers=None, timeout=30
):
    """One HTTP request. Returns (status, headers, body) without following redirects."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        payload = response.read().decode("utf-8", "replace")
        return response.status, dict(response.getheaders()), payload
    finally:
        conn.close()


class Ringmaster:
    """A ringmaster process of our own, on a port of our own."""

    def __init__(self, **overrides):
        self.port = free_port()
        env = dict(os.environ)
        # Keep probing brisk: these tests care about behaviour, not patience.
        env.update({
            "RINGMASTER_PORT": str(self.port),
            "RINGMASTER_TTL": "0",
            "RINGMASTER_TIMEOUT": "0.4",
            "RINGMASTER_MAX_PATHS": "8",
            "RINGMASTER_DEEP": "0",
        })
        env.pop("RINGMASTER_PASSWORD", None)
        env.pop("RINGMASTER_PASSWORD_FILE", None)
        env.update({k: str(v) for k, v in overrides.items()})
        # Not a context manager: the process has to outlive this call.
        self.proc = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, RINGMASTER], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self._wait_until_up()

    def _wait_until_up(self):
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"ringmaster exited: {self.proc.communicate()[0]}")
            try:
                if request(self.port, "/healthz", timeout=2)[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                time.sleep(0.1)
        raise RuntimeError("ringmaster never answered /healthz")

    def get(self, path, **kwargs):
        """A request to this ringmaster."""
        return request(self.port, path, **kwargs)

    def stop(self):
        """Shut the process down and reap it."""
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.proc.stdout:
            self.proc.stdout.close()


class FakeApp:  # pylint: disable=too-few-public-methods
    """A stand-in service on a loopback port, serving whatever we hand it."""

    def __init__(self, routes):
        self.port = free_port()

        class Handler(BaseHTTPRequestHandler):
            """Answers from the routes table, 404s everything else."""

            protocol_version = "HTTP/1.0"

            def do_GET(self):  # pylint: disable=invalid-name
                """Serve the canned response for this path."""
                path = self.path.partition("?")[0]
                status, ctype, body = routes.get(path, (404, "text/plain", "nope"))
                raw = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # pylint: disable=redefined-builtin
                pass

        class Server(ThreadingHTTPServer):
            """Deeper backlog than the default, for the burst a scan makes."""

            request_queue_size = 64      # a scan connects to every path at once
            daemon_threads = True

        self.httpd = Server(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop serving and release the port."""
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


# A Gradio page: the title lives in a meta tag, because JS sets document.title.
GRADIO_HTML = """<!doctype html><html><head>
<meta charset="utf-8">
<meta property="og:title" content="Stable Diffusion" />
</head><body><div id="root"></div></body></html>"""

API_JSON = json.dumps({"service": "widgetd", "ui": "/web/", "version": 3})
UI_HTML = "<!doctype html><html><head><title>Widget Control</title></head><body>ok</body></html>"
OPENAPI = json.dumps({"openapi": "3.0.0", "paths": {}})


# ------------------------------------------------------------ open endpoints


class OpenEndpointTests(unittest.TestCase):
    """The endpoints that answer with no password set."""

    @classmethod
    def setUpClass(cls):
        cls.rm = Ringmaster()

    @classmethod
    def tearDownClass(cls):
        cls.rm.stop()

    def test_healthz_is_plain_ok(self):
        status, headers, body = self.rm.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, "ok")
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))

    def test_dashboard_renders(self):
        status, headers, body = self.rm.get("/")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("RING<span>MASTER</span>", body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_index_html_is_the_dashboard_too(self):
        self.assertEqual(self.rm.get("/index.html")[0], 200)

    def test_header_shows_version_and_links_to_the_project(self):
        body = self.rm.get("/")[2]
        version = re.search(r'class="ver">v([\d.]+)<', body)
        self.assertIsNotNone(version, "no version chip in the header")
        self.assertEqual(version.group(1), self._source_version())
        mark = re.search(r'<a class="mark" href="([^"]+)"[^>]*>', body)
        self.assertIsNotNone(mark, "header mark is not a link")
        self.assertEqual(mark.group(1), self._source_constant("PROJECT_URL"))
        self.assertIn('aria-label=', mark.group(0))

    def test_favicon_is_served_and_cacheable(self):
        for path in ("/favicon.svg", "/favicon.ico"):
            with self.subTest(path=path):
                status, headers, body = self.rm.get(path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "image/svg+xml; charset=utf-8")
                self.assertIn("max-age", headers["Cache-Control"])
                with open(FAVICON, encoding="utf-8") as handle:
                    self.assertEqual(body, handle.read())

    def test_apps_json_shape(self):
        status, headers, body = self.rm.get("/apps.json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        data = json.loads(body)
        self.assertEqual(sorted(data), ["apps", "hostname", "scanned_at"])
        for app in data["apps"]:
            self.assertEqual(
                sorted(app),
                ["binds", "detail", "owner", "port", "primary", "public",
                 "routes", "scheme", "source", "status", "title"],
            )

    def test_unknown_path_is_404(self):
        status, _, body = self.rm.get("/no-such-page")
        self.assertEqual(status, 404)
        self.assertEqual(body, "not found")

    def test_logout_redirects_and_clears(self):
        status, headers, _ = self.rm.get("/logout")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertIn("Max-Age=0", headers["Set-Cookie"])

    def test_rescan_produces_a_fresh_stamp(self):
        first = json.loads(self.rm.get("/apps.json")[2])["scanned_at"]
        time.sleep(1.1)
        self.assertEqual(self.rm.get("/?rescan=1")[0], 200)
        second = json.loads(self.rm.get("/apps.json")[2])["scanned_at"]
        self.assertGreater(second, first)

    @staticmethod
    def _source_constant(name):
        with open(RINGMASTER, encoding="utf-8") as handle:
            match = re.search(rf'^{name} = "([^"]+)"', handle.read(), re.M)
        return match.group(1)

    def _source_version(self):
        return self._source_constant("VERSION")


# ---------------------------------------------------------------- discovery


@unittest.skipUnless(shutil.which("ss"), "needs iproute2 (ss) to see listeners")
class DiscoveryTests(unittest.TestCase):
    """Real ports, fetched and classified for real."""

    @classmethod
    def setUpClass(cls):
        cls.gradio = FakeApp({"/": (200, "text/html", GRADIO_HTML)})
        cls.api = FakeApp({
            "/": (200, "application/json", API_JSON),
            "/web/": (200, "text/html", UI_HTML),
            "/openapi.json": (200, "application/json", OPENAPI),
        })
        cls.silent = FakeApp({})          # 404s everything: should not be listed
        cls.rm = Ringmaster(
            RINGMASTER_DEEP="1", RINGMASTER_MAX_PATHS="26", RINGMASTER_TIMEOUT="2.0",
        )
        cls.apps = {
            app["port"]: app
            for app in json.loads(cls.rm.get("/apps.json", timeout=SCAN_TIMEOUT)[2])["apps"]
        }

    @classmethod
    def tearDownClass(cls):
        cls.rm.stop()
        for app in (cls.gradio, cls.api, cls.silent):
            app.stop()

    def test_finds_the_fake_apps(self):
        self.assertIn(self.gradio.port, self.apps)
        self.assertIn(self.api.port, self.apps)

    def test_app_with_no_title_tag_is_named_from_meta(self):
        # The whole point of the Gradio fix: no <title>, but og:title says who it is.
        self.assertNotIn("<title", GRADIO_HTML)
        self.assertEqual(self.apps[self.gradio.port]["title"], "Stable Diffusion")

    def test_json_root_is_classified_as_api(self):
        routes = {r["path"]: r for r in self.apps[self.api.port]["routes"]}
        self.assertEqual(routes["/"]["kind"], "api")

    def test_ui_route_is_found_from_the_json_body(self):
        app = self.apps[self.api.port]
        routes = {r["path"]: r for r in app["routes"]}
        self.assertIn("/web/", routes, "the url in the API response was not followed")
        self.assertEqual(routes["/web/"]["kind"], "ui")
        self.assertEqual(routes["/web/"]["hint"], "url in the API response at /")
        # The card headline should point at the UI, not at the JSON root.
        self.assertEqual(app["primary"]["path"], "/web/")
        self.assertEqual(app["title"], "Widget Control")

    def test_openapi_document_is_classified_as_docs(self):
        routes = {r["path"]: r for r in self.apps[self.api.port]["routes"]}
        route = routes.get("/openapi.json")
        self.assertIsNotNone(route, "conventional paths were not probed")
        self.assertEqual(route["kind"], "docs")
        self.assertEqual(route["hint"], "common path")

    def test_port_answering_nothing_is_dropped(self):
        self.assertNotIn(self.silent.port, self.apps)

    def test_loopback_only_apps_are_marked_private(self):
        app = self.apps[self.gradio.port]
        self.assertFalse(app["public"])
        self.assertEqual(app["binds"], ["127.0.0.1"])

    def test_loopback_apps_render_unlinked(self):
        body = self.rm.get("/", timeout=SCAN_TIMEOUT)[2]
        self.assertIn("Bound to loopback", body)
        # Not linked: no href pointing at a loopback-only port.
        self.assertNotIn(f":{self.gradio.port}/", body)


# --------------------------------------------------------------------- auth


class AuthTests(unittest.TestCase):
    """With a password set, everything but the open endpoints asks first."""

    PASSWORD = "correct horse"

    @classmethod
    def setUpClass(cls):
        cls.rm = Ringmaster(RINGMASTER_PASSWORD=cls.PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.rm.stop()

    def login(self, password=None):
        """POST the login form. Returns (status, headers, body)."""
        body = urlencode_password(self.PASSWORD if password is None else password)
        return self.rm.get(
            "/login", method="POST", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )

    def test_dashboard_asks_for_the_password(self):
        status, _, body = self.rm.get("/")
        self.assertEqual(status, 200)
        self.assertIn('name="password"', body)
        self.assertNotIn("On the network", body)

    def test_apps_json_challenges_with_basic(self):
        status, headers, _ = self.rm.get("/apps.json")
        self.assertEqual(status, 401)
        self.assertIn("Basic", headers["WWW-Authenticate"])

    def test_basic_auth_works_for_scripts(self):
        status, _, body = self.rm.get("/apps.json", headers=basic_auth(self.PASSWORD))
        self.assertEqual(status, 200)
        self.assertIn("apps", json.loads(body))

    def test_wrong_basic_auth_is_refused(self):
        self.assertEqual(self.rm.get("/apps.json", headers=basic_auth("nope"))[0], 401)

    def test_open_endpoints_stay_open(self):
        self.assertEqual(self.rm.get("/healthz")[0], 200)
        self.assertEqual(self.rm.get("/favicon.svg")[0], 200)

    def test_login_page_has_the_icon(self):
        self.assertIn('href="/favicon.svg"', self.rm.get("/")[2])

    def test_wrong_password_says_so(self):
        status, _, body = self.login("wrong")
        self.assertEqual(status, 401)
        self.assertIn("Wrong password", body)

    def test_good_password_sets_a_guarded_cookie(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_session_cookie_opens_the_dashboard_and_logout_closes_it(self):
        cookie = session_cookie(self.login()[1]["Set-Cookie"])
        status, _, body = self.rm.get("/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("RING<span>MASTER</span>", body)

        self.assertEqual(self.rm.get("/logout", headers={"Cookie": cookie})[0], 303)
        after = self.rm.get("/", headers={"Cookie": cookie})[2]
        self.assertIn('name="password"', after, "session survived logout")

    def test_repeated_failures_earn_a_lockout(self):
        # A fresh process, so this test's failures don't leak into the others.
        rm = Ringmaster(RINGMASTER_PASSWORD="hunter2")
        try:
            body = urlencode_password("wrong")
            headers = {"Content-Type": "application/x-www-form-urlencoded",
                       "Content-Length": str(len(body))}
            seen = ""
            for _ in range(6):
                seen = request(rm.port, "/login", "POST",
                               body=body, headers=headers)[2]
            self.assertIn("Too many attempts", seen)
            # Even the right password is refused while the lockout holds.
            good = urlencode_password("hunter2")
            locked = request(
                rm.port, "/login", "POST", body=good,
                headers={**headers, "Content-Length": str(len(good))},
            )[2]
            self.assertIn("Too many attempts", locked)
        finally:
            rm.stop()


# -------------------------------------------------------------- installer CLI


class InstallerCliTests(unittest.TestCase):
    """Argument handling only - nothing here touches the system."""

    def run_install(self, *args):
        """install.sh with these arguments, capturing both streams."""
        return subprocess.run(
            ["bash", INSTALL_SH, *args], capture_output=True, text=True, check=False
        )

    def test_help_explains_itself(self):
        done = self.run_install("--help")
        self.assertEqual(done.returncode, 0)
        self.assertIn("sudo ./scripts/install.sh", done.stdout)

    def test_bad_port_is_refused_before_anything_happens(self):
        done = self.run_install("--port", "99999")
        self.assertEqual(done.returncode, 1)
        self.assertIn("bad port", done.stderr)

    def test_unknown_option_is_refused(self):
        done = self.run_install("--wat")
        self.assertEqual(done.returncode, 1)
        self.assertIn("unknown option", done.stderr)


# ------------------------------------------------------------------ helpers


def urlencode_password(password):
    """The login form body."""
    return urllib.parse.urlencode({"password": password})


def basic_auth(password):
    """The header curl -u :password would send."""
    token = base64.b64encode(f":{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def session_cookie(set_cookie_header):
    """Just the name=value pair, for sending back."""
    return set_cookie_header.split(";")[0]


if __name__ == "__main__":
    unittest.main(verbosity=2)
