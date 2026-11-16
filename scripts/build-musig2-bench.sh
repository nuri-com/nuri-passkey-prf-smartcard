#!/usr/bin/env bash
# Build only: temporary AID4 benchmark, never a release artifact or installer.
# Profiles the current card/musig2 sources without changing tracked release sources.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${JC_KIT:?set JC_KIT}"
ANT_JAVACARD="${ANT_JAVACARD:-$ROOT/tools/ant-javacard-proven.jar}"
JAVA8_HOME="${JAVA8_HOME:-$(/usr/libexec/java_home -v 1.8)}"
CAP_OUT="${CAP_OUT:-$ROOT/.build/musig2-bench.cap}"
CAP_OUT="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$CAP_OUT")"
B="$(mktemp -d)"
trap 'rm -rf "$B"' EXIT
mkdir -p "$B/src/nuri/musig2" "$(dirname "$CAP_OUT")"
cp "$ROOT"/card/musig2/*.java "$B/src/nuri/musig2/"
cp "$ROOT/card/bench/MuSig2Bench.java" "$B/src/nuri/musig2/"
python3 - "$B/src/nuri/musig2/RsaMultiply.java" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
needle='    void clear() {'
assert s.count(needle)==1
s=s.replace(needle,'''    // Injected only into the temporary, non-release benchmark build.
    void benchInit() { rsa.init(key, Cipher.MODE_ENCRYPT); }
    void benchSquare() { rsa.init(key, Cipher.MODE_ENCRYPT); input[95] = 3; square((short)0); }
    void benchFold(boolean field) {
        Util.arrayFillNonAtomic(work,(short)0,(short)64,(byte)0xa5);
        rsa.init(key, Cipher.MODE_ENCRYPT);
        reduce(field);
        clear();
    }
''' + needle)
p.write_text(s)
PY
cat > "$B/build.xml" <<EOF
<project name="NuriMuSig2Bench" default="build" basedir=".">
  <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="$ANT_JAVACARD"/>
  <target name="build"><javacard jckit="$JC_KIT">
    <cap aid="4E5552494D554734" version="1.0" output="$B/raw.cap" sources="src" jca="3.0.4">
      <applet class="nuri.musig2.MuSig2Bench" aid="4E5552494D55473401"/>
    </cap>
  </javacard></target>
</project>
EOF
(cd "$B" && JAVA_HOME="$JAVA8_HOME" ant -q)
python3 "$ROOT/scripts/normalize-cap.py" "$B/raw.cap" "$CAP_OUT"
shasum -a 256 "$CAP_OUT"
