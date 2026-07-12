#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/mobile/expo-nfc-prf-probe"
EXPORT_DIR="$ROOT/.build/expo-v1/android-export"

"$ROOT/scripts/prepare-expo-v1.sh"

cd "$APP"
npm ci
npm run check:design-system
npm run typecheck

EXPO_PUBLIC_ASP_BASE=https://example.com/v4 \
EXPO_PUBLIC_NODE_URL=https://example.com \
EXPO_PUBLIC_NURI_RP_ID=example.com \
EXPO_PUBLIC_NURI_ORIGIN=https://example.com \
EXPO_PUBLIC_NURI_CREDENTIAL_ID=test \
EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY=test \
npx expo export --platform android --output-dir "$EXPORT_DIR" --clear

test -f "$EXPORT_DIR/metadata.json"
echo "EXPO_V1_SOURCE_BUNDLE_VERIFIED"

if [[ "${EXPO_NATIVE_ANDROID:-}" == "YES" ]]; then
  DEFAULT_ANDROID_HOME="$HOME/Library/Android/sdk"
  if [[ -d /opt/homebrew/share/android-commandlinetools/ndk/27.1.12297006 ]]; then
    DEFAULT_ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
  fi
  ANDROID_HOME="${ANDROID_HOME:-$DEFAULT_ANDROID_HOME}"
  JAVA17_HOME="${JAVA17_HOME:-${JAVA_HOME:-}}"
  if { [[ -z "$JAVA17_HOME" ]] || ! "$JAVA17_HOME/bin/java" -version 2>&1 | head -1 | grep -Eq 'version "17\.'; } && \
     [[ -x /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home/bin/java ]]; then
    JAVA17_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
  fi
  [[ -d "$ANDROID_HOME" ]] || {
    echo "Android SDK not found. Set ANDROID_HOME." >&2
    exit 1
  }
  [[ -x "$JAVA17_HOME/bin/java" ]] || {
    echo "JDK 17 not found. Set JAVA17_HOME." >&2
    exit 1
  }
  "$JAVA17_HOME/bin/java" -version 2>&1 | head -1 | grep -Eq 'version "17\.' || {
    echo "JAVA17_HOME does not point to JDK 17: $JAVA17_HOME" >&2
    exit 1
  }
  (
    cd "$APP/android"
    ANDROID_HOME="$ANDROID_HOME" ANDROID_SDK_ROOT="$ANDROID_HOME" JAVA_HOME="$JAVA17_HOME" \
      ./gradlew app:assembleDebug -PreactNativeArchitectures="${EXPO_ANDROID_ARCH:-arm64-v8a}"
  )
  test -f "$APP/android/app/build/outputs/apk/debug/app-debug.apk"
  echo "EXPO_V1_ANDROID_NATIVE_VERIFIED"
fi
