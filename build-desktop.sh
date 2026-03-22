#!/usr/bin/env bash
set -euo pipefail
echo "=== Building Overlord Desktop ==="
cd "$(dirname "$0")/Overlord-Desktop"
npm install
npm run build
echo "=== Done ==="
