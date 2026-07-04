#!/usr/bin/env bash
# Build the passport WebAssembly adapter.
set -euo pipefail
cd "$(dirname "$0")"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ./wasm_exec.js
GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o passport.wasm .
echo "built passport.wasm ($(du -h passport.wasm | cut -f1))"
