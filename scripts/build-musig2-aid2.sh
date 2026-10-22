#!/usr/bin/env bash
# Build the MuSig2 v1.15/PIN2 applet under a SECOND AID so it installs next to
# an older MuSig2 instance (package 4E5552494D5547 / applet 4E5552494D554701)
# without any GlobalPlatform DELETE. Source is card/musig2 unchanged except
# APPLET_AID, which becomes 4E5552494D55473201 (package 4E5552494D554732).
#
# Env: JC_KIT (jc304_kit path), ANT_JAVACARD (ant-javacard-proven.jar),
#      JAVA8_HOME (JDK 8 for the converter), CAP_OUT (default dist/nuri-musig2-v20-keygen-aid2.cap).
# scripts/build-card-v1-release.sh calls this and normalizes the CAP like the others.
#
# Install (never deletes): GP_BIN=~/bin/gp; "$GP_BIN" --install dist/nuri-musig2-v20-keygen-aid2.cap
# Host scripts select it with NURI_MUSIG2_AID=4E5552494D55473201.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${JC_KIT:?set JC_KIT=/path/to/jc304_kit}"
ANT_JAVACARD="${ANT_JAVACARD:-$ROOT/tools/ant-javacard-proven.jar}"
JAVA8_HOME="${JAVA8_HOME:-$(/usr/libexec/java_home -v 1.8)}"
CAP_OUT="${CAP_OUT:-$ROOT/dist/nuri-musig2-v20-keygen-aid2.cap}"
B="$(mktemp -d)"
trap 'rm -rf "$B"' EXIT
mkdir -p "$B/src/nuri/musig2"
cp "$ROOT"/card/musig2/*.java "$B/src/nuri/musig2/"
perl -0pi -e 's/\(byte\)0x4D, \(byte\)0x55, \(byte\)0x47, \(byte\)0x01\n/(byte)0x4D, (byte)0x55, (byte)0x47, (byte)0x32, (byte)0x01\n/' \
  "$B/src/nuri/musig2/NuriMuSig2v019.java"
grep -q '(byte)0x47, (byte)0x32, (byte)0x01' "$B/src/nuri/musig2/NuriMuSig2v019.java" \
  || { echo "APPLET_AID patch did not apply" >&2; exit 1; }
cat > "$B/build.xml" <<EOF
<project name="NuriMuSig2AID2" default="build" basedir=".">
  <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="$ANT_JAVACARD"/>
  <target name="build">
    <javacard jckit="$JC_KIT">
      <cap aid="4E5552494D554732" version="2.2" output="$CAP_OUT" sources="src" jca="3.0.4">
        <applet class="nuri.musig2.NuriMuSig2v019" aid="4E5552494D55473201"/>
      </cap>
    </javacard>
  </target>
</project>
EOF
(cd "$B" && JAVA_HOME="$JAVA8_HOME" ant -q)
shasum -a 256 "$CAP_OUT"
