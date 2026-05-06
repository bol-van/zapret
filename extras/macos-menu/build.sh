#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_NAME="Zapret Menu.app"
BUILD_DIR="${SCRIPT_DIR}/build"
APP_DIR="${BUILD_DIR}/${APP_NAME}"
MACOS_DIR="${APP_DIR}/Contents/MacOS"
RESOURCES_DIR="${APP_DIR}/Contents/Resources"

command -v swiftc >/dev/null 2>&1 || {
  echo "swiftc is required. Install Xcode Command Line Tools first." >&2
  exit 1
}

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/Contents/Info.plist"
cp "$SCRIPT_DIR/Resources/ZapretIcon.icns" "$RESOURCES_DIR/ZapretIcon.icns"

swiftc "$SCRIPT_DIR/Sources/ZapretMenu.swift" \
  -o "$MACOS_DIR/Zapret Menu" \
  -framework Cocoa

chmod +x "$MACOS_DIR/Zapret Menu"
touch "$APP_DIR"

echo "$APP_DIR"
