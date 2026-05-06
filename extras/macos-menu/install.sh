#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_NAME="Zapret Menu.app"
ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/Applications/Zapret Control"}
APP_PATH="$INSTALL_DIR/$APP_NAME"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/org.zapret.menu.plist"
SUDOERS_FILE="/etc/sudoers.d/zapret-menu"
HELPER_SRC="$SCRIPT_DIR/zapret-menu-helper"
HELPER_DST="$ZAPRET_BASE/zapret-menu-helper"

[ "$(uname)" = "Darwin" ] || {
  echo "This menu app is macOS-only." >&2
  exit 1
}

[ -d "$ZAPRET_BASE" ] || {
  echo "zapret is not installed at $ZAPRET_BASE. Run install_easy.sh first or set ZAPRET_BASE." >&2
  exit 1
}

APP_BUILT=$("$SCRIPT_DIR/build.sh")
mkdir -p "$INSTALL_DIR"
rm -rf "$APP_PATH"
cp -R "$APP_BUILT" "$APP_PATH"
xattr -dr com.apple.quarantine "$APP_PATH" 2>/dev/null || true

echo "Installing privileged helper and sudoers rule. You may be asked for your macOS password."
sudo install -m 0755 -o root -g wheel "$HELPER_SRC" "$HELPER_DST"

TMP_SUDOERS=$(mktemp)
CURRENT_USER=$(id -un)
cat >"$TMP_SUDOERS" <<EOF
$CURRENT_USER ALL=(root) NOPASSWD: $HELPER_DST start, $HELPER_DST stop, $HELPER_DST restart, $HELPER_DST update
EOF
sudo visudo -cf "$TMP_SUDOERS"
sudo install -m 0440 -o root -g wheel "$TMP_SUDOERS" "$SUDOERS_FILE"
rm -f "$TMP_SUDOERS"

mkdir -p "$HOME/Library/LaunchAgents"
cat >"$LAUNCH_AGENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.zapret.menu</string>
  <key>ProgramArguments</key>
  <array>
    <string>$APP_PATH/Contents/MacOS/Zapret Menu</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>StandardOutPath</key>
  <string>/tmp/zapret-menu.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/zapret-menu.err.log</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)" "$LAUNCH_AGENT" 2>/dev/null || true
pkill -x "Zapret Menu" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$LAUNCH_AGENT"

echo "Installed: $APP_PATH"
echo "LaunchAgent: $LAUNCH_AGENT"
echo "Helper: $HELPER_DST"
echo "sudoers: $SUDOERS_FILE"
