#!/usr/bin/env python3
"""Compare semantic CAP contents while ignoring ZIP container metadata."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path


CREATION_TIME = re.compile(rb"(?m)^Java-Card-CAP-Creation-Time: .*\r?$")


def contents(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        result = {}
        for name in archive.namelist():
            data = archive.read(name)
            if name == "META-INF/MANIFEST.MF":
                data = CREATION_TIME.sub(
                    b"Java-Card-CAP-Creation-Time: <normalized>", data
                )
            result[name] = data
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("expected", type=Path)
    parser.add_argument("actual", type=Path)
    args = parser.parse_args()

    expected = contents(args.expected)
    actual = contents(args.actual)
    names = sorted(set(expected) | set(actual))
    differences = []
    for name in names:
        if name not in expected:
            differences.append(f"only in actual: {name}")
        elif name not in actual:
            differences.append(f"only in expected: {name}")
        elif expected[name] != actual[name]:
            left = hashlib.sha256(expected[name]).hexdigest()
            right = hashlib.sha256(actual[name]).hexdigest()
            differences.append(f"different: {name} ({left} != {right})")

    if differences:
        print("CAP_COMPONENTS_DIFFER", file=sys.stderr)
        print("\n".join(differences), file=sys.stderr)
        raise SystemExit(1)

    print(f"CAP_COMPONENTS_IDENTICAL {args.expected.name} {args.actual.name}")


if __name__ == "__main__":
    main()
