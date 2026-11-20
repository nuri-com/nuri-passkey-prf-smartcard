#!/usr/bin/env bash
# Build native macOS mini app "Nuri Card Setup.app" (PIV PIN change + macOS login pairing).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="${1:-$HOME/Applications/Nuri Card Setup.app}"
BIN_DIR="$APP_DIR/Contents/MacOS"

mkdir -p "$BIN_DIR"
swiftc -O -parse-as-library \
  "$ROOT/mac/NuriCardSetup.swift" \
  -o "$BIN_DIR/NuriCardSetup"

cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>NuriCardSetup</string>
  <key>CFBundleIdentifier</key>
  <string>com.nuri.card.macsetup</string>
  <key>CFBundleName</key>
  <string>Nuri Card Setup</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NuriRepoPath</key>
  <string>${ROOT}</string>
</dict>
</plist>
PLIST

codesign --force --deep -s - "$APP_DIR" >/dev/null 2>&1 || true
printf 'MAC_PIV_APP_BUILT %s\n' "$APP_DIR"
