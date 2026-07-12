#!/usr/bin/env python3
"""Rewrite a CAP ZIP with stable ordering, timestamps, and file attributes."""

from __future__ import annotations

import argparse
import re
import tempfile
import zipfile
from pathlib import Path


STABLE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
CREATION_TIME = re.compile(rb"(?m)^Java-Card-CAP-Creation-Time: .*\r?$")


def normalize(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source, "r") as archive:
        entries = []
        for name in sorted(archive.namelist()):
            data = archive.read(name)
            if name == "META-INF/MANIFEST.MF":
                data = CREATION_TIME.sub(
                    b"Java-Card-CAP-Creation-Time: Thu Jan 01 00:00:00 UTC 1970",
                    data,
                )
            entries.append((name, data))

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temp_path = Path(temporary.name)

    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, STABLE_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
        temp_path.replace(destination)
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    normalize(args.source, args.destination or args.source)


if __name__ == "__main__":
    main()
