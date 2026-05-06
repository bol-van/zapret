#!/bin/sh
set -eu

ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/Applications/Zapret Control"}
APP_PATH="$INSTALL_DIR/Zapret Menu.app"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/org.zapret.menu.plist"
SUDOERS_FILE="/etc/sudoers.d/zapret-menu"
HELPER_DST="$ZAPRET_BASE/zapret-menu-helper"

[ "$(uname)" = "Darwin" ] || {
  echo "This menu app is macOS-only." >&2
  exit 1
}

launchctl bootout "gui/$(id -u)" "$LAUNCH_AGENT" 2>/dev/null || true
pkill -x "Zapret Menu" 2>/dev/null || true

rm -f "$LAUNCH_AGENT"
rm -rf "$APP_PATH"

echo "Removing privileged helper and sudoers rule. You may be asked for your macOS password."
sudo rm -f "$HELPER_DST" "$SUDOERS_FILE"

echo "Zapret Menu removed."
