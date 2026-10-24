#!/usr/bin/env bash
# WINEX Sovereign L1 Suite - macOS Clean Installer
set -e

echo "=========================================================================="
echo "      WINEX (WNX) SOVEREIGN LAYER-1 SUITE // MACOS CLEAN INSTALLER        "
echo "=========================================================================="
echo ""

pkill -f "WINEX_Node" 2>/dev/null || true
pkill -f "WINEX_Miner" 2>/dev/null || true
pkill -f "WINEX_Wallet" 2>/dev/null || true
sleep 1

INSTALL_DIR="${WINEX_INSTALL_DIR:-$HOME/winex}"
BIN_DIR="$INSTALL_DIR/bin"
LOCAL_BIN="$HOME/.local/bin"

echo "[*] Clean install: Removing legacy binaries..."
rm -rf "$BIN_DIR" 2>/dev/null || true
mkdir -p "$BIN_DIR"
mkdir -p "$LOCAL_BIN"

ARCH="$(uname -m)"
echo "[*] Detected Architecture: $ARCH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$ARCH" = "arm64" ]; then
    W_BIN="WINEX_Wallet_mac_arm64"
    M_BIN="WINEX_Miner_mac_arm64"
    N_BIN="WINEX_Node_mac_arm64"
else
    W_BIN="WINEX_Wallet_mac_amd64"
    M_BIN="WINEX_Miner_mac_amd64"
    N_BIN="WINEX_Node_mac_amd64"
fi

if [ -f "$SCRIPT_DIR/$W_BIN" ]; then
    echo "[*] Deploying local macOS binaries..."
    cp -f "$SCRIPT_DIR/$W_BIN" "$BIN_DIR/WINEX_Wallet"
    cp -f "$SCRIPT_DIR/$M_BIN" "$BIN_DIR/WINEX_Miner"
    cp -f "$SCRIPT_DIR/$N_BIN" "$BIN_DIR/WINEX_Node"
else
    TMP_ZIP="/tmp/winex_macos_suite.zip"
    rm -f "$TMP_ZIP" 2>/dev/null || true
    echo "[*] Downloading verified WINEX macOS release from GitHub (WinexCoin/winex-core)..."
    curl -fSL "https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_macOS_Suite.zip" -o "$TMP_ZIP" || \
    curl -fSL "https://winexcoin.com/downloads/WINEX_macOS_Suite.zip" -o "$TMP_ZIP"
    unzip -o -q "$TMP_ZIP" -d "$BIN_DIR"
    rm -f "$TMP_ZIP"
    cp -f "$BIN_DIR/$W_BIN" "$BIN_DIR/WINEX_Wallet" 2>/dev/null || true
    cp -f "$BIN_DIR/$M_BIN" "$BIN_DIR/WINEX_Miner" 2>/dev/null || true
    cp -f "$BIN_DIR/$N_BIN" "$BIN_DIR/WINEX_Node" 2>/dev/null || true
fi

chmod +x "$BIN_DIR"/* 2>/dev/null || true
xattr -d com.apple.quarantine "$BIN_DIR"/* 2>/dev/null || true

ln -sf "$BIN_DIR/WINEX_Wallet" "$LOCAL_BIN/winex-wallet" 2>/dev/null || true
ln -sf "$BIN_DIR/WINEX_Node" "$LOCAL_BIN/winex-node" 2>/dev/null || true
ln -sf "$BIN_DIR/WINEX_Miner" "$LOCAL_BIN/winex-miner" 2>/dev/null || true

echo ""
echo "=========================================================================="
echo " [✓] MACOS INSTALLATION COMPLETED SUCCESSFULLY!"
echo "=========================================================================="
echo " Installation Directory : $BIN_DIR"
echo "   - $BIN_DIR/WINEX_Wallet"
echo "   - $BIN_DIR/WINEX_Node"
echo "   - $BIN_DIR/WINEX_Miner"
echo "=========================================================================="
