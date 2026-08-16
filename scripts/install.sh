#!/usr/bin/env bash
#
# Install ringmaster: copies the script into place, writes a systemd unit,
# optionally sets a password, and starts the service.
#
#   sudo ./scripts/install.sh                      # port 80, no password
#   sudo ./scripts/install.sh --port 8080          # different port
#   sudo ./scripts/install.sh --ask-password       # prompt, store in /etc/ringmaster.pw
#   sudo ./scripts/install.sh --password 'hunter2' # non-interactive
#   sudo ./scripts/install.sh --no-start           # install but don't enable/start
#
# Re-running is safe: it upgrades the script and unit in place.

set -euo pipefail

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
PW_FILE="${PW_FILE:-/etc/ringmaster.pw}"
SERVICE="ringmaster"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # repo root - ringmaster.py lives there
UNIT_SRC="$SRC_DIR/systemd/$SERVICE.service"

PORT="80"
PASSWORD=""
ASK_PASSWORD=0
SET_PASSWORD=0
NO_START=0

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
warn() { printf '%s warn%s %s\n' "$YEL" "$OFF" "$*" >&2; }
die()  { printf '%serror%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

usage() {
  sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)        PORT="${2:?--port needs a number}"; shift 2 ;;
    --password)    PASSWORD="${2:?--password needs a value}"; SET_PASSWORD=1; shift 2 ;;
    --ask-password) ASK_PASSWORD=1; SET_PASSWORD=1; shift ;;
    --no-start)    NO_START=1; shift ;;
    -h|--help)     usage ;;
    *)             die "unknown option: $1 (try --help)" ;;
  esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT > 0 && PORT < 65536 )) || die "bad port: $PORT"

# ---------------------------------------------------------------- preflight

step "Checking prerequisites"

if [[ $EUID -ne 0 && "${SKIP_ROOT_CHECK:-0}" != "1" ]]; then
  die "run this with sudo — it writes to $BIN_DIR and $UNIT_DIR"
fi

[[ -f "$SRC_DIR/ringmaster.py" ]] || die "ringmaster.py not found in $SRC_DIR"
[[ -f "$UNIT_SRC" ]] || die "systemd/$SERVICE.service not found in $SRC_DIR"

command -v python3 >/dev/null || die "python3 not found (apt install python3)"
python3 - <<'PY' || die "python3 3.8+ required"
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
say "  python3 $(python3 -c 'import platform;print(platform.python_version())')"

command -v ss >/dev/null || warn "ss not found — install iproute2 or ringmaster sees no host services"
command -v docker >/dev/null || say "  ${DIM}docker not found — container discovery will be skipped${OFF}"

HAVE_SYSTEMD=0
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] && HAVE_SYSTEMD=1
(( HAVE_SYSTEMD )) || warn "systemd not available — installing files only"

# Is something already sitting on the port? Our own service doesn't count -
# it runs as plain `python3`, so match on its pid rather than its name.
if command -v ss >/dev/null; then
  HOLDER="$(ss -tlnpH 2>/dev/null | awk -v p=":$PORT\$" '$4 ~ p {print; exit}' || true)"
  HOLDER_PID="$(printf '%s' "$HOLDER" | sed -n 's/.*pid=\([0-9]\{1,\}\).*/\1/p')"
  OUR_PID=0
  if (( HAVE_SYSTEMD )); then
    OUR_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
    OUR_PID="${OUR_PID:-0}"
  fi
  if [[ -n "$HOLDER_PID" && "$HOLDER_PID" == "$OUR_PID" ]]; then
    say "  port $PORT is held by $SERVICE (pid $OUR_PID) — it will be restarted"
  elif [[ -n "$HOLDER" && "$HOLDER" != *ringmaster* ]]; then
    warn "port $PORT already has a listener:"
    warn "  $(printf '%s' "$HOLDER" | tr -s ' ')"
    warn "ringmaster will fail to bind until that frees up (or use --port)"
  fi
fi

# ----------------------------------------------------------------- password

if (( ASK_PASSWORD )); then
  read -rsp "Password for the dashboard: " PASSWORD; echo
  read -rsp "Again: " CONFIRM; echo
  [[ "$PASSWORD" == "$CONFIRM" ]] || die "passwords didn't match"
  [[ -n "$PASSWORD" ]] || die "empty password — omit --ask-password to run without one"
fi

if (( SET_PASSWORD )); then
  step "Writing password file"
  umask 077
  printf '%s\n' "$PASSWORD" > "$PW_FILE"
  chmod 600 "$PW_FILE"
  say "  $PW_FILE (mode 600)"
elif [[ -f "$PW_FILE" ]]; then
  say "  keeping the existing password in $PW_FILE"
  SET_PASSWORD=1
fi

# ------------------------------------------------------------------ install

step "Installing files"
install -d "$BIN_DIR" "$UNIT_DIR"
install -m 755 "$SRC_DIR/ringmaster.py" "$BIN_DIR/ringmaster.py"
say "  $BIN_DIR/ringmaster.py"

UNIT="$UNIT_DIR/$SERVICE.service"
install -m 644 "$UNIT_SRC" "$UNIT"

# Point ExecStart at wherever we actually put the script, and apply options.
sed -i "s|^ExecStart=.*|ExecStart=$BIN_DIR/ringmaster.py|" "$UNIT"
sed -i "s|^Environment=RINGMASTER_PORT=.*|Environment=RINGMASTER_PORT=$PORT|" "$UNIT"
sed -i "/^Environment=RINGMASTER_PASSWORD/d" "$UNIT"
if (( SET_PASSWORD )); then
  sed -i "/^Environment=RINGMASTER_PORT=/a Environment=RINGMASTER_PASSWORD_FILE=$PW_FILE" "$UNIT"
fi
say "  $UNIT"

# -------------------------------------------------------------------- start

if (( ! HAVE_SYSTEMD )); then
  say ""
  say "Files are in place. Start it yourself with:"
  say "  sudo RINGMASTER_PORT=$PORT $BIN_DIR/ringmaster.py"
  exit 0
fi

systemctl daemon-reload

if (( NO_START )); then
  say ""
  say "Installed but not started. When you're ready:"
  say "  sudo systemctl enable --now $SERVICE"
  exit 0
fi

if systemctl is-active --quiet "$SERVICE"; then
  step "Restarting $SERVICE"
else
  step "Starting $SERVICE"
fi

systemctl enable "$SERVICE" >/dev/null 2>&1 || systemctl enable "$SERVICE"
# restart, not `enable --now`: --now does nothing when the unit is already
# running, so an upgrade would land the new script on disk and leave the old
# one serving. restart also starts it if it was stopped, so it covers both.
systemctl restart "$SERVICE"
sleep 1

if ! systemctl is-active --quiet "$SERVICE"; then
  say ""
  warn "$SERVICE didn't stay running. Recent log:"
  journalctl -u "$SERVICE" -n 20 --no-pager || true
  exit 1
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SUFFIX=""; [[ "$PORT" != "80" ]] && SUFFIX=":$PORT"

say ""
printf '%sringmaster is up%s\n' "$GRN" "$OFF"
say "  http://$(hostname)$SUFFIX"
[[ -n "$IP" ]] && say "  http://$IP$SUFFIX"
if (( SET_PASSWORD )); then
  say "  password required (stored in $PW_FILE)"
else
  say "  no password — anyone who can reach the port can see the dashboard"
  say "  ${DIM}add one later: sudo ./scripts/install.sh --ask-password${OFF}"
fi
say ""
say "  logs:    journalctl -u $SERVICE -f"
say "  restart: sudo systemctl restart $SERVICE"
