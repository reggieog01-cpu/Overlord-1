#!/usr/bin/env bash
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="${PLUGIN_DIR}/native"
PLUGIN_NAME="bot-killer"
ZIP_OUT="${PLUGIN_DIR}/${PLUGIN_NAME}.zip"

pushd "${NATIVE_DIR}" >/dev/null

echo "[build] GOOS=windows GOARCH=amd64"
GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 \
  GOOS=windows GOARCH=amd64 \
  CC=x86_64-w64-mingw32-gcc \
  /usr/local/go/bin/go build -buildmode=c-shared \
  -o "${PLUGIN_DIR}/${PLUGIN_NAME}-windows-amd64.dll" .

popd >/dev/null

rm -f "${ZIP_OUT}"
(cd "${PLUGIN_DIR}" && zip -q "${ZIP_OUT}" \
  "${PLUGIN_NAME}-windows-amd64.dll" \
  "${PLUGIN_NAME}.html" \
  "${PLUGIN_NAME}.css" \
  "${PLUGIN_NAME}.js")

echo "[ok] ${ZIP_OUT}"
