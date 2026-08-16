#!/usr/bin/env bash
#
# Remove ringmaster.
#
#   sudo ./scripts/uninstall.sh          # stop, disable, remove script + unit
#   sudo ./scripts/uninstall.sh --purge  # also delete the password file
#
# Nothing else on the box is touched: ringmaster only ever read from it.

set -euo pipefail

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
PW_FILE="${PW_FILE:-/etc/ringmaster.pw}"
SERVICE="ringmaster"
PURGE=0

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'; OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
die()  { printf '%serror%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
gone() { printf '  removed %s\n' "$1"; }
skip() { printf '  %snot present: %s%s\n' "$DIM" "$1" "$OFF"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

if [[ $EUID -ne 0 && "${SKIP_ROOT_CHECK:-0}" != "1" ]]; then
  die "run this with sudo"
fi

if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
  step "Stopping the service"
  if systemctl list-unit-files 2>/dev/null | grep -q "^$SERVICE.service"; then
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    say "  stopped and disabled $SERVICE"
  else
    skip "$SERVICE.service (not registered)"
  fi
fi

step "Removing files"
for target in "$UNIT_DIR/$SERVICE.service" "$BIN_DIR/ringmaster.py"; do
  if [[ -e "$target" ]]; then rm -f "$target"; gone "$target"; else skip "$target"; fi
done

if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
fi

if [[ -f "$PW_FILE" ]]; then
  if (( PURGE )); then
    rm -f "$PW_FILE"; gone "$PW_FILE"
  else
    say "  kept $PW_FILE ${DIM}(delete it with --purge)${OFF}"
  fi
fi

say ""
printf '%sringmaster is gone%s\n' "$GRN" "$OFF"
