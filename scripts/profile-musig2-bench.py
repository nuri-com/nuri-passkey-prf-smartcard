#!/usr/bin/env python3
"""Time the throwaway AID4 only; never installs, deletes, keys or sets a PIN."""
import argparse
import json
import statistics
import time
from pathlib import Path
from smartcard.System import readers

AID = bytes.fromhex("4E5552494D55473401")
OPS = ["noop", "rsa_init", "rsa_square_including_init", "multiply_n", "multiply_p",
       "fold_n", "fold_p", "ecdh_scalar_one", "sha256_32", "rng_32", "validate_point"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--reader", default="OMNIKEY")
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 255 or args.samples < 1:
        parser.error("repetitions must be 1..255; samples must be positive")
    matches = []
    for reader in readers():
        if args.reader not in str(reader):
            continue
        conn = reader.createConnection()
        try:
            conn.connect()
        except Exception:
            continue
        matches.append((str(reader), conn))
    if len(matches) != 1:
        for _, conn in matches:
            conn.disconnect()
        raise RuntimeError(f"expected one connected {args.reader} reader; got {len(matches)}")
    reader, conn = matches[0]
    try:
        _, sw1, sw2 = conn.transmit([0, 0xA4, 4, 0, len(AID), *AID])
        if (sw1, sw2) != (0x90, 0):
            raise RuntimeError(f"temporary benchmark not selected: {sw1:02x}{sw2:02x}")
        results = []
        for op, name in enumerate(OPS):
            elapsed = []
            for _ in range(args.samples):
                before = time.perf_counter_ns()
                data, sw1, sw2 = conn.transmit([0x80, 0x70, op, args.repetitions, 0])
                ms = (time.perf_counter_ns() - before) / 1_000_000
                if (sw1, sw2) != (0x90, 0) or len(data) != 32:
                    raise RuntimeError(f"{name} failed: {sw1:02x}{sw2:02x}, length={len(data)}")
                elapsed.append(ms)
            results.append({"operation": name, "apdu_ms": elapsed,
                            "median_ms_per_op": statistics.median(elapsed) / args.repetitions})
        baseline = results[0]["median_ms_per_op"]
        for result in results:
            result["baseline_subtracted_ms_per_op"] = result["median_ms_per_op"] - baseline
        payload = {"aid": AID.hex().upper(), "reader": reader,
                   "repetitions": args.repetitions, "samples": args.samples,
                   "notes": "Host wall-clock; no-op subtraction includes common ECDH key setup. "
                            "Square includes rsa.init; subtract rsa_init for an estimate. "
                            "Fold data is public deterministic nonzero input.",
                   "results": results}
        Path(args.output).write_text(json.dumps(payload, indent=2) + "\n")
        print("| Operation | Median ms/op | No-op subtracted ms/op |")
        print("|---|---:|---:|")
        for row in results:
            print(f"| {row['operation']} | {row['median_ms_per_op']:.3f} | "
                  f"{row['baseline_subtracted_ms_per_op']:.3f} |")
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()
