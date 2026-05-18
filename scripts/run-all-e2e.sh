#!/usr/bin/env bash
set -euo pipefail

npm test
npm run musig2:demo
npm run fido2:test-prf
