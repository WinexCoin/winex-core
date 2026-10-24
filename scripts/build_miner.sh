#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"

mkdir -p "${BIN_DIR}"
cd "${ROOT_DIR}/cmd/winex-miner"

echo "==> Building WINEX Miner (CPU Engine, Cross-Platform)..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-miner" .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-miner.exe" .
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-miner-mac-amd64" .
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-miner-mac-arm64" .

# Native OpenCL CGO engine for Linux if OpenCL headers are available
if [ -f /usr/include/CL/cl.h ] || [ -f ./CL/cl.h ]; then
    echo "==> Building WINEX Dedicated OpenCL GPU Miner (Linux amd64)..."
    GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o "${BIN_DIR}/winex-miner-opencl" . || echo "Note: OpenCL native build requires libOpenCL.so.1"
fi

echo "✔ WINEX Miner build complete. Output located in: ${BIN_DIR}"
