# Changelog

Notable changes to ringmaster. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Site icon — three rings on a red field — shown in the browser tab for both the
  dashboard and the login page. Served at `/favicon.svg`, and at `/favicon.ico`
  for browsers that ask for that path unprompted.
- `/favicon.svg` answers before the auth check, like `/healthz`, so the icon
  appears on the login page rather than being swallowed by the password
  challenge.
- The mark now also sits inline beside the RINGMASTER wordmark in the page
  header, with the version shown next to it as a `v0.1.0` chip.
- Link to the project on GitHub at the foot of the dashboard.

### Changed

- `_send()` takes a `cache` argument. It still defaults to `Cache-Control:
  no-store` for every existing response; only the favicon opts into
  `public, max-age=86400` so browsers stop refetching it on every page load.

### Fixed

- `install.sh` now restarts the service instead of running
  `systemctl enable --now`, which does nothing when the unit is already active.
  Re-running the installer over a running service copied the new script into
  place and left the old one serving from memory, so an upgrade appeared to do
  nothing until the service was restarted by hand.
- The port preflight no longer warns about ringmaster's own listener. It matched
  the string `ringmaster` in the `ss` line, but the unit runs as plain
  `python3`; it now compares the holder's pid against the unit's `MainPID` and
  says the port will be restarted rather than warning of a conflict.

### Notes

- The SVG is embedded in `ringmaster.py` rather than shipped alongside it —
  `install.sh` copies only the one script to `/usr/local/bin`, so a sibling file
  would never reach the installed service. `ringmaster-favicon.svg` in the repo
  is the same artwork; edit both together.

## [0.1.0] — 2026-08-15

Initial version. One Python file, standard library only.

### Added

- **Port discovery** from `ss -tlnp` (listening TCP ports, owning process and
  pids) and `docker ps` (running containers and their published host ports).
  Docker-published ports are matched back to their container, so a card reads
  `jellyfin` rather than `docker-proxy`.
- **Liveness probing** — every port found is actually fetched over HTTP, with a
  TLS handshake as fallback, so databases, SSH and brokers drop out on their own.
- **Route discovery** from the app's own response at `/` (HTML links, JSON url
  fields, `Link:` headers, redirects), `/proc/<pid>/environ` and `cmdline`
  (`BASE_URL`, `--root-path`, and friends), UI directories in `/proc/<pid>/cwd`,
  `docker inspect` env, Traefik `PathPrefix` labels and bind-mount sources, plus
  a list of conventional paths. Every candidate is fetched before it is listed.
- **Route classification** into app, api and docs, with byte-identical responses
  collapsed to the shortest path, and the card headline linked to the best UI
  route rather than `/`. Hovering a route pill names the hint it came from.
- **Loopback section** — services bound only to `127.0.0.1` are shown but not
  linked, since a link to them from another machine wouldn't work.
- **Optional password**, off by default, via `RINGMASTER_PASSWORD` or the
  preferred `RINGMASTER_PASSWORD_FILE`. A correct password sets an `HttpOnly`,
  `SameSite=Lax` session cookie; comparison is constant-time; five bad guesses
  from one address earn a 60-second lockout; a Lock button ends the session.
  `/apps.json` also accepts HTTP Basic so `curl -u :password` works.
- **Endpoints** — `/` the dashboard, `/?rescan=1` a forced sweep, `/apps.json`
  the whole scan as JSON, `/logout`, and an unauthenticated `/healthz`.
- **Configuration** by environment: `RINGMASTER_PORT`, `RINGMASTER_TTL`,
  `RINGMASTER_TIMEOUT`, `RINGMASTER_MAX_PATHS`, `RINGMASTER_DEEP`,
  `RINGMASTER_SESSION_HOURS`.
- **`install.sh` / `uninstall.sh`** and a systemd unit. Install copies the script
  to `/usr/local/bin`, enables the service and prints the URL; re-running
  upgrades in place and keeps an existing password file.
