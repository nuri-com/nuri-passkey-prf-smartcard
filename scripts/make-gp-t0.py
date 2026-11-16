#!/usr/bin/env python3
"""Patch only GlobalPlatformPro's default PC/SC protocol from * to T=0.

Does not implement or alter SCP authentication. Use the official v26.06.04 JAR.
"""
from pathlib import Path
import argparse
import zipfile

p = argparse.ArgumentParser()
p.add_argument("source", type=Path)
p.add_argument("output", type=Path)
a = p.parse_args()
old = b"\x01\x00\x01*"
new = b"\x01\x00\x03T=0"
with zipfile.ZipFile(a.source) as zin, zipfile.ZipFile(a.output, "w") as zout:
    for info in zin.infolist():
        data = zin.read(info.filename)
        if info.filename == "apdu4j/pcsc/Readers.class":
            # static initializer: ldc_w String #284 ("*") -> #278 ("T=0")
            before, after = b"\x13\x01\x1c", b"\x13\x01\x16"
            if data.count(before) != 2:
                raise RuntimeError("Unexpected GlobalPlatformPro version; refusing to patch")
            pos = data.rfind(before)
            data = data[:pos] + after + data[pos + len(before):]
        elif info.filename in {
            "apdu4j/pcsc/TerminalManager.class",
            "jnasmartcardio/Smartcardio$JnaCardTerminal.class",
        }:
            if data.count(old) != 1:
                raise RuntimeError(f"Unexpected class layout: {info.filename}")
            data = data.replace(old, new)
        zout.writestr(info, data)
