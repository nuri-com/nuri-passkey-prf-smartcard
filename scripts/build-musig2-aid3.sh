#!/usr/bin/env bash
# Build a normalized MuSig2 CAP under a third, additive identity.
# No card access. Sources are copied; the tracked APPLET_AID is never changed.
# Env: JC_KIT, ANT_JAVACARD, JAVA8_HOME, CAP_OUT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${JC_KIT:?set JC_KIT=/path/to/jc304_kit}"
ANT_JAVACARD="${ANT_JAVACARD:-$ROOT/tools/ant-javacard-proven.jar}"
JAVA8_HOME="${JAVA8_HOME:-$(/usr/libexec/java_home -v 1.8)}"
CAP_OUT="${CAP_OUT:-$ROOT/dist/nuri-musig2-v20-keygen-aid3.cap}"
# Resolve caller-relative output before entering the temporary build directory.
CAP_OUT="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$CAP_OUT")"
B="$(mktemp -d)"
trap 'rm -rf "$B"' EXIT
mkdir -p "$B/src/nuri/musig2" "$(dirname "$CAP_OUT")"
cp "$ROOT"/card/musig2/*.java "$B/src/nuri/musig2/"
python3 - "$B/src/nuri/musig2/NuriMuSig2v019.java" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
source = path.read_text()
old = '(byte)0x4D, (byte)0x55, (byte)0x47, (byte)0x01\n'
new = '(byte)0x4D, (byte)0x55, (byte)0x47, (byte)0x33, (byte)0x01\n'
if source.count(old) != 1:
    raise SystemExit('APPLET_AID patch expected exactly one source match')
path.write_text(source.replace(old, new, 1))
PY
cat > "$B/build.xml" <<EOF
<project name="NuriMuSig2AID3" default="build" basedir=".">
  <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="$ANT_JAVACARD"/>
  <target name="build">
    <javacard jckit="$JC_KIT">
      <cap aid="4E5552494D554733" version="2.2" output="$B/raw.cap" sources="src" jca="3.0.4">
        <applet class="nuri.musig2.NuriMuSig2v019" aid="4E5552494D55473301"/>
      </cap>
    </javacard>
  </target>
</project>
EOF
(cd "$B" && JAVA_HOME="$JAVA8_HOME" ant -q)
python3 "$ROOT/scripts/normalize-cap.py" "$B/raw.cap" "$CAP_OUT"
shasum -a 256 "$CAP_OUT"
