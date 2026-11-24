#!/usr/bin/env bash
# Build native macOS mini app "Nuri Card Setup.app" (PIV, pairing and Feitian fingerprints).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="${1:-$HOME/Applications/Nuri Card Setup.app}"
BIN_DIR="$APP_DIR/Contents/MacOS"
RES_DIR="$APP_DIR/Contents/Resources"

mkdir -p "$BIN_DIR" "$RES_DIR"
swiftc -O -parse-as-library \
  "$ROOT/mac/NuriCardSetup.swift" \
  -o "$BIN_DIR/NuriCardSetup"

ICON_PLIST=""
if [ -f "$ROOT/mac/AppIcon.png" ] && command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  ICONSET="$TMP_DIR/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 128 256 512; do
    sips -z "$sz" "$sz" "$ROOT/mac/AppIcon.png" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
    sz2=$((sz * 2))
    sips -z "$sz2" "$sz2" "$ROOT/mac/AppIcon.png" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$RES_DIR/AppIcon.icns"
  ICON_PLIST=$'  <key>CFBundleIconFile</key>\n  <string>AppIcon</string>'
fi

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
${ICON_PLIST}
  <key>NuriRepoPath</key>
  <string>${ROOT}</string>
</dict>
</plist>
PLIST

codesign --force --deep -s - "$APP_DIR" >/dev/null 2>&1 || true
touch "$APP_DIR"
printf 'MAC_PIV_APP_BUILT %s\n' "$APP_DIR"
