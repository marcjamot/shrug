#!/bin/bash
# Builds Shrug.app (menu bar app with shrug inside) into apps/mac/build/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

swift build -c release
BIN=$(swift build -c release --show-bin-path)
APP="$HERE/build/Shrug.app"
VERSION=$(git -C "$HERE" describe --tags --always 2>/dev/null || echo dev)

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN/ShrugApp" "$APP/Contents/MacOS/Shrug"
mkdir -p "$APP/Contents/Helpers"
cp "$BIN/shrug" "$APP/Contents/Helpers/shrug"
cat >"$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>app.shrug.Shrug</string>
  <key>CFBundleName</key><string>Shrug</string>
  <key>CFBundleDisplayName</key><string>Shrug</string>
  <key>CFBundleExecutable</key><string>Shrug</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
# Ad-hoc signature: enough for a personal build. The Touch ID key lives in the
# Secure Enclave and is not tied to the signature, so rebuilding keeps it working.
codesign --force --sign - "$APP/Contents/Helpers/shrug"
codesign --force --sign - "$APP"
echo "Built $APP"
