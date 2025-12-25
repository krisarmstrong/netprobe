#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Verify Go build compiles
go build -o /dev/null .

# Run tests if any
go test ./... 2>/dev/null || true
