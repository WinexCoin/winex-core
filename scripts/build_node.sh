#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"

mkdir -p "${BIN_DIR}"
cd "${ROOT_DIR}/cmd/winex-node"

echo "==> Building WINEX Node for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-node" .

echo "==> Building WINEX Node for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-node.exe" .

echo "==> Building WINEX Node for macOS (Universal)..."
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-node-mac-amd64" .
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-node-mac-arm64" .

echo "✔ WINEX Node build complete. Output located in: ${BIN_DIR}"
