#!/usr/bin/env bash
# Source this helper before any build downloads or simulator environment setup.
# Gradle is an external tool; do not restore a vendored wrapper to satisfy it.
require_system_gradle() {
  local requested="${GRADLE_BIN:-gradle}"
  local version_output major minor
  GRADLE_BIN="$(command -v "$requested")" || {
    echo "Gradle 8.2 or newer is required. Install it separately and put gradle on PATH, or set GRADLE_BIN to its absolute executable path (not found: $requested)." >&2
    return 1
  }
  if [[ "$GRADLE_BIN" != /* ]]; then
    GRADLE_BIN="$(cd "$(dirname "$GRADLE_BIN")" && pwd)/$(basename "$GRADLE_BIN")"
  fi
  if ! version_output="$("$GRADLE_BIN" --version 2>&1)"; then
    printf '%s\n' "$version_output" >&2
    echo "Gradle 8.2 or newer is required, but $GRADLE_BIN --version failed. Check the Gradle installation and its Java runtime." >&2
    return 1
  fi
  if [[ ! "$version_output" =~ Gradle[[:space:]]+([0-9]+)\.([0-9]+)(\.[0-9]+)?([[:space:]]|$) ]]; then
    printf '%s\n' "$version_output" >&2
    echo "Could not determine the installed Gradle version. Gradle 8.2 or newer is required." >&2
    return 1
  fi
  GRADLE_VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  if (( 10#$major < 8 || (10#$major == 8 && 10#$minor < 2) )); then
    echo "Gradle 8.2 or newer is required; found $GRADLE_VERSION at $GRADLE_BIN. Install a supported version separately or set GRADLE_BIN." >&2
    return 1
  fi
  if (( 10#$major >= 9 )); then
    echo "Gradle 8.2 or newer within 8.x is required; found $GRADLE_VERSION at $GRADLE_BIN. The upstream Java Card plugin 1.8.0 uses ClosureBackedAction, removed in Gradle 9. Install Gradle 8.2 separately and set GRADLE_BIN." >&2
    return 1
  fi
}
