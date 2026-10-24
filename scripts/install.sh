#!/usr/bin/env bash
# WINEX Sovereign L1 Suite - Linux Home Installer (Clean, Minimalist & Organized)
set -e

echo "=========================================================================="
echo "        WINEX (WNX) SOVEREIGN LAYER-1 SUITE // LINUX HOME INSTALLER       "
echo "=========================================================================="
echo ""

# 1. Terminate any running WINEX processes
echo "[*] Terminating existing WINEX processes..."
pkill -f "WINEX_Node" 2>/dev/null || true
pkill -f "WINEX_Miner" 2>/dev/null || true
pkill -f "WINEX_Wallet" 2>/dev/null || true
sleep 1

# 2. Target installation directory: $HOME/winex (Visible, clean folder)
INSTALL_DIR="$HOME/winex"
BIN_DIR="$INSTALL_DIR/bin"
LOCAL_BIN="$HOME/.local/bin"

echo "[*] Installation directory: $INSTALL_DIR (Desktop is kept clean)"

# 3. Clean wipe any old WINEX files from Desktop and legacy directories
echo "[*] Cleaning up legacy files and desktop clutter..."
for D in "$HOME/Desktop" "$HOME/Masaüstü"; do
    if [ -d "$D" ]; then
        rm -rf "$D/WINEX" 2>/dev/null || true
        rm -f "$D"/WINEX*.desktop "$D"/"WINEX Wallet" "$D"/"WINEX Miner" "$D"/"WINEX Node" "$D"/WINEX*.AppImage 2>/dev/null || true
    fi
done

# Clean legacy hidden .winex bin if exists
rm -rf "$HOME/.winex/bin" "$HOME/.winex/runtime" 2>/dev/null || true

# Prepare clean install directories
mkdir -p "$BIN_DIR"
mkdir -p "$LOCAL_BIN"

# Clean any clutter in root of install dir
rm -rf "$INSTALL_DIR"/*.desktop "$INSTALL_DIR"/WINEX_*.sh "$INSTALL_DIR"/README*.txt "$INSTALL_DIR"/install.sh 2>/dev/null || true

# 4. Source binaries into bin/
TMP_ZIP="/tmp/winex_linux_suite.zip"
rm -f "$TMP_ZIP" 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/WINEX_Wallet_Linux" ] && [ -f "$SCRIPT_DIR/WINEX_Node_Linux" ] && [ -f "$SCRIPT_DIR/WINEX_Miner_Linux" ]; then
    echo "[*] Deploying binaries to $BIN_DIR..."
    cp -f "$SCRIPT_DIR/WINEX_Wallet_Linux" "$BIN_DIR/WINEX_Wallet"
    cp -f "$SCRIPT_DIR/WINEX_Node_Linux" "$BIN_DIR/WINEX_Node"
    cp -f "$SCRIPT_DIR/WINEX_Miner_Linux" "$BIN_DIR/WINEX_Miner"
    [ -f "$SCRIPT_DIR/README.md" ] && cp -f "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
else
    echo "[*] Downloading verified WINEX Linux release from GitHub (WinexCoin/winex-core)..."
    curl -fSL "https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Linux_Suite.zip" -o "$TMP_ZIP" || \
    curl -fSL "https://winexcoin.com/downloads/WINEX_Linux_Suite.zip" -o "$TMP_ZIP"
    unzip -o -q "$TMP_ZIP" -d "$BIN_DIR"
    rm -f "$TMP_ZIP"
    [ -f "$BIN_DIR/WINEX_Wallet_Linux" ] && mv -f "$BIN_DIR/WINEX_Wallet_Linux" "$BIN_DIR/WINEX_Wallet"
    [ -f "$BIN_DIR/WINEX_Node_Linux" ] && mv -f "$BIN_DIR/WINEX_Node_Linux" "$BIN_DIR/WINEX_Node"
    [ -f "$BIN_DIR/WINEX_Miner_Linux" ] && mv -f "$BIN_DIR/WINEX_Miner_Linux" "$BIN_DIR/WINEX_Miner"
    [ -f "$BIN_DIR/README.md" ] && mv -f "$BIN_DIR/README.md" "$INSTALL_DIR/"
    rm -f "$BIN_DIR"/install.sh "$BIN_DIR"/README*.txt "$BIN_DIR"/*.desktop 2>/dev/null || true
fi

# Move logo to bin if present
[ -f "$INSTALL_DIR/winex_logo_128.png" ] && mv -f "$INSTALL_DIR/winex_logo_128.png" "$BIN_DIR/" 2>/dev/null || true

chmod +x "$BIN_DIR"/WINEX_* 2>/dev/null || true

# 5. System Icons & Desktop Environment Configuration
ICONS_DIR="$HOME/.local/share/icons/hicolor/128x128/apps"
mkdir -p "$ICONS_DIR"
if [ -f "$BIN_DIR/winex_logo_128.png" ]; then
    cp -f "$BIN_DIR/winex_logo_128.png" "$ICONS_DIR/winex.png"
    cp -f "$BIN_DIR/winex_logo_128.png" "$ICONS_DIR/winex-wallet.png"
    cp -f "$BIN_DIR/winex_logo_128.png" "$ICONS_DIR/winex-miner.png"
    cp -f "$BIN_DIR/winex_logo_128.png" "$ICONS_DIR/winex-node.png"
    cp -f "$BIN_DIR/winex_logo_128.png" "$ICONS_DIR/WINEX_Wallet.png"
fi
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

# Configure KDE Plasma to execute scripts on double click without prompt
kwriteconfig6 --file kdeglobals --group "Executable scripts" --key "behaviourOnLaunch" "alwaysExecute" 2>/dev/null || kwriteconfig5 --file kdeglobals --group "Executable scripts" --key "behaviourOnLaunch" "alwaysExecute" 2>/dev/null || true
kwriteconfig6 --file kiorc --group "Executable scripts" --key "behaviourOnLaunch" "alwaysExecute" 2>/dev/null || kwriteconfig5 --file kiorc --group "Executable scripts" --key "behaviourOnLaunch" "alwaysExecute" 2>/dev/null || true

# CLI symlinks in ~/.local/bin
ln -sf "$BIN_DIR/WINEX_Wallet" "$LOCAL_BIN/winex-wallet"
ln -sf "$BIN_DIR/WINEX_Node" "$LOCAL_BIN/winex-node"
ln -sf "$BIN_DIR/WINEX_Miner" "$LOCAL_BIN/winex-miner"

# 6. Create clean 1-click launchers in root of ~/winex
cat << 'SH' > "$INSTALL_DIR/start_wallet.sh"
#!/usr/bin/env bash
# WINEX Sovereign GUI Wallet Launcher (Pure GUI - Zero Terminal Window)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/bin/WINEX_Wallet"
cd "$DIR"
exec "$BIN" "$@"
SH

cat << 'SH' > "$INSTALL_DIR/start_miner.sh"
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/bin/WINEX_Miner"

if [ ! -t 0 ] && [ ! -t 1 ]; then
    for t in konsole gnome-terminal ptyxis kgx xfce4-terminal kitty alacritty mate-terminal lxterminal xterm; do
        if command -v "$t" >/dev/null 2>&1; then
            case "$t" in
                konsole) exec "$t" --hold --workdir "$DIR" -e bash "$0" "$@" ;;
                gnome-terminal|ptyxis|kgx) exec "$t" --working-directory="$DIR" -- bash "$0" "$@" ;;
                *) exec "$t" -e bash -c "\"$0\" \"\$@\"; echo ''; read -n 1 -s -r -p 'Press [Enter] to close...'" ;;
            esac
        fi
    done
fi

cd "$DIR"
exec "$BIN" "$@"
SH

cat << 'SH' > "$INSTALL_DIR/start_node.sh"
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/bin/WINEX_Node"

if [ ! -t 0 ] && [ ! -t 1 ]; then
    for t in konsole gnome-terminal ptyxis kgx xfce4-terminal kitty alacritty mate-terminal lxterminal xterm; do
        if command -v "$t" >/dev/null 2>&1; then
            case "$t" in
                konsole) exec "$t" --hold --workdir "$DIR" -e bash "$0" "$@" ;;
                gnome-terminal|ptyxis|kgx) exec "$t" --working-directory="$DIR" -- bash "$0" "$@" ;;
                *) exec "$t" -e bash -c "\"$0\" \"\$@\"; echo ''; read -n 1 -s -r -p 'Press [Enter] to close...'" ;;
            esac
        fi
    done
fi

cd "$DIR"
exec "$BIN" "$@"
SH

chmod +x "$INSTALL_DIR"/start_*.sh 2>/dev/null || true

# 7. Create Branded Logo Launchers (.desktop) inside ~/winex and Start Menu
cat << EOF > "$INSTALL_DIR/WINEX_Wallet.desktop"
[Desktop Entry]
Type=Application
Name=WINEX Wallet
Comment=WINEX Sovereign Cryptocurrency Desktop Wallet
Exec=$INSTALL_DIR/start_wallet.sh
Icon=$ICONS_DIR/winex.png
Terminal=false
Categories=Finance;Network;
StartupNotify=true
StartupWMClass=winex-wallet
EOF

cat << EOF > "$INSTALL_DIR/WINEX_Miner.desktop"
[Desktop Entry]
Type=Application
Name=WINEX Miner
Comment=WINEX Hybrid OpenCL / CPU Blockchain Miner
Exec=$INSTALL_DIR/start_miner.sh
Icon=$ICONS_DIR/winex.png
Terminal=true
Categories=Finance;Network;
StartupNotify=true
StartupWMClass=winex-miner
EOF

cat << EOF > "$INSTALL_DIR/WINEX_Node.desktop"
[Desktop Entry]
Type=Application
Name=WINEX Node
Comment=WINEX Full Consensus Mesh Validator Node
Exec=$INSTALL_DIR/start_node.sh
Icon=$ICONS_DIR/winex.png
Terminal=true
Categories=Finance;Network;
StartupNotify=true
StartupWMClass=winex-node
EOF

chmod +x "$INSTALL_DIR"/WINEX_*.desktop 2>/dev/null || true

# Sync to system application menu (~/.local/share/applications)
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"
cp -f "$INSTALL_DIR/WINEX_Wallet.desktop" "$APPS_DIR/winex-wallet.desktop"
cp -f "$INSTALL_DIR/WINEX_Miner.desktop" "$APPS_DIR/winex-miner.desktop"
cp -f "$INSTALL_DIR/WINEX_Node.desktop" "$APPS_DIR/winex-node.desktop"
cp -f "$INSTALL_DIR/WINEX_Wallet.desktop" "$APPS_DIR/WINEX_Wallet.desktop"
# Universal Double-Click Runners for Dolphin / File Managers
cat << 'EOF' > "$LOCAL_BIN/winex-sh-runner"
#!/usr/bin/env bash
SCRIPT="$1"
shift
if [ -f "$SCRIPT" ]; then
    chmod +x "$SCRIPT"
    DIR="$(cd "$(dirname "$SCRIPT")" && pwd)"
    cd "$DIR"
    exec bash "$SCRIPT" "$@"
fi
EOF
chmod +x "$LOCAL_BIN/winex-sh-runner" 2>/dev/null || true

cat << EOF > "$APPS_DIR/winex-sh-runner.desktop"
[Desktop Entry]
Type=Application
Name=Shell Script Runner
Exec=$LOCAL_BIN/winex-sh-runner %f
NoDisplay=true
Terminal=false
MimeType=application/x-shellscript;text/x-shellscript;
EOF

cat << 'EOF' > "$APPS_DIR/winex-desktop-launcher.desktop"
[Desktop Entry]
Type=Application
Name=Desktop Application Runner
Exec=gio launch %f
NoDisplay=true
Terminal=false
MimeType=application/x-desktop;text/x-desktop;
EOF

chmod +x "$APPS_DIR"/winex-*.desktop "$APPS_DIR"/WINEX_*.desktop 2>/dev/null || true
xdg-mime default winex-desktop-launcher.desktop application/x-desktop 2>/dev/null || true
xdg-mime default winex-desktop-launcher.desktop text/x-desktop 2>/dev/null || true
xdg-mime default winex-sh-runner.desktop application/x-shellscript 2>/dev/null || true
xdg-mime default winex-sh-runner.desktop text/x-shellscript 2>/dev/null || true
update-desktop-database "$APPS_DIR" 2>/dev/null || true
kbuildsycoca6 2>/dev/null || kbuildsycoca5 2>/dev/null || true

echo ""
echo "=========================================================================="
echo " [✓] INSTALLATION COMPLETED SUCCESSFULLY!"
echo "=========================================================================="
echo " Clean Workspace        : $INSTALL_DIR"
echo " 1-Click Launchers      :"
echo "   - Wallet  : $INSTALL_DIR/start_wallet.sh"
echo "   - Node    : $INSTALL_DIR/start_node.sh"
echo "   - Miner   : $INSTALL_DIR/start_miner.sh"
echo ""
echo " Internal Binaries      : $INSTALL_DIR/bin/"
echo " Documentation          : $INSTALL_DIR/README.md"
echo ""
echo " CLI Terminal Commands  :"
echo "   $ winex-wallet"
echo "   $ winex-node"
echo "   $ winex-miner"
echo ""
echo " Desktop Status         : Clean (zero files on desktop)."
echo "=========================================================================="
