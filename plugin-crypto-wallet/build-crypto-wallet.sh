#!/usr/bin/env bash
# Build script for the crypto-wallet Overlord plugin.
# Only produces Windows binaries. Cross-compilation requires a Windows-targeting
# C toolchain (e.g. x86_64-w64-mingw32-gcc) when building from Linux/macOS.
#
# Usage:
#   ./build-crypto-wallet.sh
#   BUILD_TARGETS="windows-amd64 windows-arm64" ./build-crypto-wallet.sh
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="${PLUGIN_DIR}/native"
PLUGIN_NAME="crypto-wallet"
ZIP_OUT="${PLUGIN_DIR}/${PLUGIN_NAME}.zip"

if [[ ! -d "${NATIVE_DIR}" ]]; then
  echo "[error] native/ folder not found: ${NATIVE_DIR}" >&2
  exit 1
fi

pushd "${NATIVE_DIR}" >/dev/null

# Default: windows-amd64 only.
DEFAULT_TARGETS="windows-amd64"
BUILD_TARGETS="${BUILD_TARGETS:-${DEFAULT_TARGETS}}"

BUILT_FILES=()

for target in ${BUILD_TARGETS}; do
  os="${target%%-*}"
  arch="${target#*-}"

  case "${os}" in
    windows) ext="dll" ;;
    darwin)  ext="dylib" ;;
    *)       ext="so" ;;
  esac

  outfile="${PLUGIN_DIR}/${PLUGIN_NAME}-${os}-${arch}.${ext}"
  echo "[build] GOOS=${os} GOARCH=${arch} → ${outfile}"
  CGO_ENABLED=1 GOOS="${os}" GOARCH="${arch}" \
    go build -buildmode=c-shared -o "${outfile}" .
  BUILT_FILES+=("${PLUGIN_NAME}-${os}-${arch}.${ext}")
done

popd >/dev/null

# Remove old zip
rm -f "${ZIP_OUT}"

ZIP_FILES=()
for bf in "${BUILT_FILES[@]}"; do
  ZIP_FILES+=("${bf}")
done

# Add web assets
for asset in "${PLUGIN_NAME}.html" "${PLUGIN_NAME}.css" "${PLUGIN_NAME}.js"; do
  if [[ -f "${PLUGIN_DIR}/${asset}" ]]; then
    ZIP_FILES+=("${asset}")
  fi
done

if command -v zip >/dev/null 2>&1; then
  (cd "${PLUGIN_DIR}" && zip -q "${ZIP_OUT}" "${ZIP_FILES[@]}")
else
  echo "[error] 'zip' not found — install it and re-run." >&2
  exit 1
fi

echo "[ok] ${ZIP_OUT}"
