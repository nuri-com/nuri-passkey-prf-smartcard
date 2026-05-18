#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8765}"

cd "$ROOT/web"
echo "Serving WebAuthn PRF test page at http://localhost:$PORT/prf-test.html"
python3 -m http.server "$PORT" --bind 127.0.0.1
