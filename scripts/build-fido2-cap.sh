#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "FIDO2 is part of the atomic Card V1 artifact set; building all applets."
exec "$ROOT/scripts/build-card-v1-release.sh"
