#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================="
echo "    WINEX CORE // COMPREHENSIVE SUITE BUILDER     "
echo "=================================================="

bash "${SCRIPT_DIR}/build_node.sh"
bash "${SCRIPT_DIR}/build_wallet.sh"
bash "${SCRIPT_DIR}/build_miner.sh"

echo ""
echo "✔ All WINEX components successfully built!"
echo "Check the 'bin/' folder for cross-platform binaries."
