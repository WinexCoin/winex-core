#!/usr/bin/env python3
"""
WINEX Core Sovereign Wallet v4.0.0
Institutional-grade non-custodial cryptocurrency desktop client.
Design Language: Modern Fintech (Exodus / Ledger Live / Trust Wallet aesthetic)
Security: AES-256-GCM encryption, BIP-39 mnemonic, Zero hardcoded keys, Two-stage transaction approval.
"""

import os
os.environ["QT_LOGGING_RULES"] = "qt.qpa.services=false;qt.qpa.*=false;qt.qpa.wayland=false"

import sys
import io
import json
import time
import re
import secrets
import subprocess
import threading
import hashlib
import requests
import qrcode
import ecdsa
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QDoubleSpinBox, QMessageBox,
    QFrame, QTextEdit, QDialog, QFormLayout, QGridLayout,
    QComboBox, QCheckBox, QProgressBar, QScrollArea, QFileDialog, QInputDialog,
    QTabWidget, QTabBar
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QEvent, QSize
from PySide6.QtGui import QFont, QPixmap, QColor, QIcon, QImage, QPainter, QAction

# ==================== CONSTANTS & PATHS ====================
DEFAULT_NODE = "https://winexcoin.com"
BOOTSTRAP_NODES = [
    "https://winexcoin.com",
    "http://130.61.60.162:8081",
    "http://127.0.0.1:8081"
]
WALLET_DIR = os.path.expanduser("~/.winex")
WALLET_FILE = os.path.join(WALLET_DIR, "wallet.dat")
VAULT_V3_FILE = os.path.join(WALLET_DIR, "vault.v3.json")
MINER_ADDR_FILE = os.path.join(WALLET_DIR, "miner_address.txt")
CONFIG_FILE = os.path.join(WALLET_DIR, "wallet_config.json")
LOGO_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "winex_logo.png"),
    os.path.expanduser("~/winex/bin/winex_logo_128.png"),
    os.path.expanduser("~/.local/share/icons/hicolor/128x128/apps/winex.png"),
    os.path.expanduser("~/.local/share/icons/hicolor/128x128/apps/winex-wallet.png"),
]
LOGO_PATH = next((p for p in LOGO_CANDIDATES if os.path.exists(p)), "")

def sync_miner_address_file(address: str):
    if not address or not address.startswith("WNX"):
        return
    try:
        os.makedirs(WALLET_DIR, mode=0o700, exist_ok=True)
        with open(MINER_ADDR_FILE, "w") as f:
            f.write(address.strip())
        os.chmod(MINER_ADDR_FILE, 0o600)
    except Exception:
        pass

def ensure_background_node():
    """The WINEX node is embedded inside the wallet launcher process (127.0.0.1:8081).
    No separate node process is ever spawned from here; it stops when the wallet closes."""
    return

mnemo = Mnemonic("english")

# ==================== CRYPTOGRAPHY & SECURITY HELPERS ====================

def harden_process_security():
    """Electrum / Bitcoin Core hardening: Disable Linux core dumping & ptrace memory inspection"""
    try:
        if sys.platform.startswith("linux"):
            import ctypes
            libc = ctypes.CDLL(None)
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0)
    except Exception:
        pass

def ensure_secure_permissions():
    """Ensure wallet folder is chmod 700 and wallet file is chmod 600"""
    os.makedirs(WALLET_DIR, mode=0o700, exist_ok=True)
    if os.path.exists(WALLET_FILE):
        try:
            os.chmod(WALLET_FILE, 0o600)
        except Exception:
            pass

def save_wallet_file_atomic(file_path: str, enc_data: dict):
    """
    Electrum-Grade Atomic Disk Commit:
    1. Writes to temporary file in ~/.winex/
    2. Executes os.fsync to force physical write to drive storage
    3. Creates redundant backup copy wallet.dat.bak
    4. Performs atomic inode swap via os.replace (zero corruption risk on power loss)
    """
    ensure_secure_permissions()
    dir_name = os.path.dirname(file_path)
    tmp_path = os.path.join(dir_name, f".wallet_tmp_{os.getpid()}_{secrets.token_hex(4)}.dat")

    if os.path.exists(file_path):
        try:
            bak_path = file_path + ".bak"
            import shutil
            shutil.copy2(file_path, bak_path)
            os.chmod(bak_path, 0o600)
        except Exception:
            pass

    try:
        with open(tmp_path, "w") as f:
            json.dump(enc_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, file_path)
        os.chmod(file_path, 0o600)
    except Exception as e:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise e

def encrypt_wallet_data(data_dict: dict, password: str) -> dict:
    """Institutional AES-256-GCM Keystore with Scrypt Memory-Hard KDF (RFC 7914)"""
    salt = os.urandom(16)
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        kdf = Scrypt(salt=salt, length=32, n=16384, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
        kdf_name = "Scrypt"
    except Exception:
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        kdf_name = "PBKDF2-HMAC-SHA256"

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(data_dict).encode('utf-8'), None)
    return {
        "version": 4,
        "algorithm": "AES-256-GCM",
        "kdf": kdf_name,
        "n": 16384 if kdf_name == "Scrypt" else None,
        "iterations": 100000 if kdf_name != "Scrypt" else None,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

def has_any_wallet_file() -> bool:
    return os.path.exists(WALLET_FILE) or os.path.exists(VAULT_V3_FILE)

def load_encrypted_wallet_dict() -> dict:
    if os.path.exists(WALLET_FILE):
        with open(WALLET_FILE, "r") as f:
            return json.load(f)
    if os.path.exists(VAULT_V3_FILE):
        with open(VAULT_V3_FILE, "r") as f:
            return json.load(f)
    raise FileNotFoundError("No wallet file found")

def decrypt_wallet_data(enc_dict: dict, password: str) -> dict:
    salt = bytes.fromhex(enc_dict['salt'])
    nonce = bytes.fromhex(enc_dict['nonce'])
    ciphertext = bytes.fromhex(enc_dict['ciphertext'])
    kdf_name = enc_dict.get('kdf', 'PBKDF2-HMAC-SHA256')

    if kdf_name == "Scrypt":
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        n_val = enc_dict.get('n', 16384)
        kdf = Scrypt(salt=salt, length=32, n=n_val, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
    else:
        iterations = enc_dict.get('iterations') or 100000
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    data = json.loads(plaintext.decode('utf-8'))
    data = ensure_wallet_accounts(data)
    if "address" in data:
        sync_miner_address_file(data["address"])
    return data

def derive_hd_account(seed_phrase: str, index: int = 0, label: str = "", passphrase: str = "") -> dict:
    seed_phrase = " ".join(seed_phrase.strip().split())
    seed = mnemo.to_seed(seed_phrase, passphrase=passphrase)
    if index == 0:
        priv_bytes = hashlib.sha256(seed).digest()
    else:
        priv_bytes = hashlib.sha256(seed + f":WINEX_HD_ACCOUNT:{index}".encode("utf-8")).digest()
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    priv_hex = priv_bytes.hex()
    pub_hex = vk.to_string().hex()
    addr = "WNX" + hashlib.sha256(vk.to_string()).hexdigest()[:32].upper()
    if not label:
        label = "Primary Account" if index == 0 else f"Sub-Address #{index}"
    return {
        "index": index,
        "label": label,
        "address": addr,
        "public_key": pub_hex,
        "private_key": priv_hex,
        "derivation": f"m/44'/999'/0'/0/{index}",
        "balance": 0.0
    }

def ensure_wallet_accounts(w_data: dict) -> dict:
    if not w_data:
        return w_data
    if "accounts" not in w_data or not isinstance(w_data["accounts"], list) or len(w_data["accounts"]) == 0:
        acc0 = {
            "index": 0,
            "label": "Primary Account",
            "address": w_data.get("address", ""),
            "public_key": w_data.get("public_key", ""),
            "private_key": w_data.get("private_key", ""),
            "derivation": "m/44'/999'/0'/0/0",
            "balance": float(w_data.get("balance", 0.0))
        }
        w_data["accounts"] = [acc0]
    if "active_index" not in w_data:
        w_data["active_index"] = 0
    return w_data

def discover_hd_accounts(seed_phrase: str, passphrase: str = "", node_url: str = DEFAULT_NODE, gap_limit: int = 20) -> list:
    seed_phrase = " ".join(seed_phrase.strip().split())
    acc0 = derive_hd_account(seed_phrase, 0, "Primary Account", passphrase)
    accounts = [acc0]

    candidate_nodes = [node_url, "http://127.0.0.1:8081", "https://winexcoin.com"]
    target_node = node_url
    for cn in candidate_nodes:
        if not cn:
            continue
        try:
            r = requests.get(f"{cn}/api/state", timeout=0.8)
            if r.status_code == 200:
                target_node = cn
                break
        except Exception:
            continue

    highest_active = 0
    scanned = []
    for i in range(1, gap_limit + 1):
        cand = derive_hd_account(seed_phrase, i, f"Account #{i}", passphrase)
        bal = 0.0
        try:
            r = requests.get(f"{target_node}/api/balance/{cand['address']}", timeout=1.2)
            if r.status_code == 200:
                bal = float(r.json().get("balance", 0.0))
        except Exception:
            pass
        cand["balance"] = bal
        if bal > 0:
            highest_active = i
        scanned.append(cand)

    for i in range(highest_active):
        accounts.append(scanned[i])

    return accounts

def derive_wallet_from_seed(seed_phrase: str, passphrase: str = "") -> dict:
    seed_phrase = " ".join(seed_phrase.strip().split())
    accounts = discover_hd_accounts(seed_phrase, passphrase)
    acc0 = accounts[0]
    return {
        "seed_phrase": seed_phrase,
        "address": acc0["address"],
        "public_key": acc0["public_key"],
        "private_key": acc0["private_key"],
        "active_index": 0,
        "accounts": accounts,
        "node_url": DEFAULT_NODE
    }

def sign_transaction(private_key_hex: str, message: str) -> str:
    """RFC 6979 Deterministic SECP256k1 + SHA-256 Signature - Zero Nonce Reuse Vulnerability"""
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
    sig = sk.sign_deterministic(message.encode('utf-8'), hashfunc=hashlib.sha256)
    return sig.hex()

def validate_address_format(address: str) -> bool:
    return bool(re.match(r"^WNX[A-F0-9]{32}$", address.strip()))

# ==================== THEME STYLESHEETS ====================

DARK_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #060608;
    color: #ededf0;
}
QWidget {
    font-family: 'Sora', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 12px;
    color: #ededf0;
}
QTabWidget::pane {
    border-top: 1px solid #1e1e24;
    border-left: none;
    border-right: none;
    border-bottom: none;
    background: #060608;
}
QTabBar {
    background: #0a0a0d;
}
QTabBar::tab {
    background: #0a0a0d;
    color: #8e8e96;
    border: none;
    border-right: 1px solid #1e1e24;
    border-bottom: 1px solid #1e1e24;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 11.5px;
}
QTabBar::tab:selected {
    background: #060608;
    color: #f4f4f6;
    border-top: 2px solid #d4d4dc;
    border-bottom: 1px solid #060608;
}
QTabBar::tab:hover:!selected {
    background: #121216;
    color: #d4d4dc;
}
QFrame.card {
    background: #0a0a0d;
    border: 1px solid #1e1e24;
    border-radius: 2px;
}
QLineEdit, QDoubleSpinBox, QComboBox {
    background: #0d0d11;
    border: 1px solid #222229;
    border-radius: 2px;
    padding: 0px 8px;
    min-height: 26px;
    color: #ededf0;
    font-size: 12px;
    selection-background-color: #272730;
}
QTextEdit {
    background: #0d0d11;
    border: 1px solid #222229;
    border-radius: 2px;
    padding: 4px 8px;
    color: #ededf0;
    font-size: 12px;
    selection-background-color: #272730;
}
QLineEdit:focus, QDoubleSpinBox:focus, QComboBox:focus, QTextEdit:focus {
    border: 1px solid #52525b;
    background: #111116;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #0d0d11;
    color: #ededf0;
    border: 1px solid #272730;
    selection-background-color: #1e1e26;
    selection-color: #ffffff;
}
QPushButton {
    background: #121216;
    color: #d4d4dc;
    border: 1px solid #24242c;
    border-radius: 2px;
    padding: 0px 12px;
    min-height: 26px;
    font-weight: 600;
    font-size: 11.5px;
}
QPushButton:hover {
    background: #1a1a20;
    border-color: #383842;
    color: #ffffff;
}
QPushButton:pressed {
    background: #0a0a0d;
}
QPushButton.btn-primary {
    background: #d4d4dc;
    color: #060608;
    border: 1px solid #d4d4dc;
    font-weight: 700;
}
QPushButton.btn-primary:hover {
    background: #ededf0;
    border-color: #ededf0;
    color: #060608;
}
QPushButton.btn-secondary {
    background: #0d0d11;
    color: #d4d4dc;
    border: 1px solid #222229;
}
QPushButton.btn-secondary:hover {
    background: #16161c;
    border-color: #383842;
    color: #ffffff;
}
QTableWidget {
    background: #060608;
    alternate-background-color: #0a0a0d;
    border: 1px solid #1e1e24;
    border-radius: 0px;
    gridline-color: #141418;
    color: #d4d4dc;
    selection-background-color: #18181f;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #0a0a0d;
    color: #8e8e96;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 8px;
    border: none;
    border-bottom: 1px solid #1e1e24;
    border-right: 1px solid #141418;
}
QMenuBar {
    background-color: #08080a;
    color: #d4d4dc;
    font-size: 11.5px;
    border-bottom: 1px solid #1a1a20;
    padding: 1px 4px;
}
QMenuBar::item {
    background: transparent;
    padding: 3px 9px;
}
QMenuBar::item:selected {
    background: #16161c;
    color: #ffffff;
}
QMenu {
    background-color: #0a0a0d;
    color: #d4d4dc;
    border: 1px solid #24242c;
    padding: 2px;
}
QMenu::item {
    padding: 4px 16px;
}
QMenu::item:selected {
    background-color: #18181f;
    color: #ffffff;
}
QStatusBar {
    background-color: #08080a;
    color: #8e8e96;
    border-top: 1px solid #1a1a20;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    min-height: 22px;
}
QStatusBar::item {
    border: none;
}
"""

LIGHT_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #f8fafc;
    color: #0f172a;
}
QWidget {
    font-family: 'Sora', 'Inter', -apple-system, sans-serif;
    font-size: 12px;
    color: #0f172a;
}
QTabWidget::pane {
    border-top: 1px solid #cbd5e1;
    background: #ffffff;
}
QTabBar::tab {
    background: #f1f5f9;
    color: #475569;
    border-right: 1px solid #cbd5e1;
    border-bottom: 1px solid #cbd5e1;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 11.5px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #0f172a;
    border-top: 2px solid #0f172a;
    border-bottom: 1px solid #ffffff;
}
QFrame.card {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
}
QLineEdit, QDoubleSpinBox, QComboBox {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    padding: 0px 8px;
    min-height: 26px;
    border-radius: 2px;
    color: #0f172a;
    font-size: 12px;
}
QTextEdit {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    padding: 4px 8px;
    border-radius: 2px;
    color: #0f172a;
    font-size: 12px;
}
QPushButton {
    background: #f1f5f9;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
    padding: 0px 12px;
    min-height: 26px;
    font-weight: 600;
    font-size: 11.5px;
}
QPushButton.btn-primary {
    background: #0f172a;
    color: #ffffff;
    border: 1px solid #0f172a;
    font-weight: 700;
}
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    gridline-color: #e2e8f0;
}
QHeaderView::section {
    background: #f1f5f9;
    color: #475569;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 8px;
    border: none;
    border-bottom: 1px solid #cbd5e1;
    border-right: 1px solid #e2e8f0;
}
QMenuBar {
    background-color: #f1f5f9;
    color: #0f172a;
    border-bottom: 1px solid #cbd5e1;
}
QStatusBar {
    background-color: #f1f5f9;
    color: #475569;
    border-top: 1px solid #cbd5e1;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    min-height: 22px;
}
"""

# ==================== ONBOARDING WIZARD DIALOG ====================

class OnboardingWizardDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WINEX - Sovereign Wallet Setup")
        self.setFixedSize(620, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.generated_seed = ""
        self.quiz_indices = []

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 14, 16, 14)

        self.stack = QStackedWidget()
        self.layout.addWidget(self.stack)

        self.init_welcome_screen()
        self.init_seed_display_screen()
        self.init_seed_quiz_screen()
        self.init_password_screen()

        self.result_wallet_data = None
        self.result_password = ""

    def init_welcome_screen(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(12)

        t = QLabel("Keystore Initialization (BIP-39 / SECP256k1)")
        t.setFont(QFont("Sora", 13, QFont.Weight.Bold))
        l.addWidget(t)

        desc = QLabel("Select how to initialize your local encrypted keystore (~/.winex/wallet.dat). Private keys are derived deterministically on-device and encrypted with AES-256-GCM.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        l.addWidget(desc)

        l.addSpacing(10)

        btn_create = QPushButton("Create New 12-Word Master Seed")
        btn_create.setProperty("class", "btn-primary")
        btn_create.setFixedHeight(34)
        btn_create.clicked.connect(self.go_to_create_seed)
        l.addWidget(btn_create)

        btn_import = QPushButton("Restore Existing 12-Word Seed Phrase...")
        btn_import.setProperty("class", "btn-secondary")
        btn_import.setFixedHeight(34)
        btn_import.clicked.connect(self.go_to_import_seed)
        l.addWidget(btn_import)
        l.addStretch()

        self.stack.addWidget(w)

    def init_seed_display_screen(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        t = QLabel("BIP-39 Master Seed Generation")
        t.setFont(QFont("Sora", 13, QFont.Weight.Bold))
        l.addWidget(t)

        warn_card = QFrame()
        warn_card.setStyleSheet("background: #0d1016; border: 1px solid #1c2230; border-left: 1px solid #f43f5e; border-radius: 2px; padding: 10px;")
        wl = QVBoxLayout(warn_card)
        wl.setSpacing(4)
        w_title = QLabel("Physical Offline Backup Required")
        w_title.setStyleSheet("color: #f43f5e; font-weight: 700; font-size: 11.5px; border: none;")
        wl.addWidget(w_title)
        w_desc = QLabel(
            "Write all 12 words in exact numerical order on paper. "
            "Loss of this phrase permanently revokes access to all derived HD accounts."
        )
        w_desc.setWordWrap(True)
        w_desc.setStyleSheet("color: #cbd5e1; font-size: 11px; border: none;")
        wl.addWidget(w_desc)
        l.addWidget(warn_card)

        # 3x4 Seed Grid
        self.seed_grid_widget = QWidget()
        self.seed_grid = QGridLayout(self.seed_grid_widget)
        self.seed_grid.setSpacing(6)
        l.addWidget(self.seed_grid_widget)

        self.chk_saved = QCheckBox("I have recorded all 12 words offline.")
        self.chk_saved.setStyleSheet("font-weight: 600; margin-top: 6px;")
        self.chk_saved.toggled.connect(lambda b: self.btn_next_quiz.setEnabled(b))
        l.addWidget(self.chk_saved)

        btn_row = QHBoxLayout()
        btn_back = QPushButton("Back")
        btn_back.setProperty("class", "btn-secondary")
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        btn_row.addWidget(btn_back)

        self.btn_copy_seed = QPushButton("📋 Copy Words")
        self.btn_copy_seed.setProperty("class", "btn-secondary")
        self.btn_copy_seed.clicked.connect(self.copy_generated_seed)
        btn_row.addWidget(self.btn_copy_seed)

        btn_row.addStretch()

        self.btn_next_quiz = QPushButton("Verify Backup")
        self.btn_next_quiz.setProperty("class", "btn-primary")
        self.btn_next_quiz.setEnabled(False)
        self.btn_next_quiz.clicked.connect(self.setup_and_go_quiz)
        btn_row.addWidget(self.btn_next_quiz)

        l.addLayout(btn_row)
        self.stack.addWidget(w)

    def init_seed_quiz_screen(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(16)

        t = QLabel("Verify Your Backup")
        t.setFont(QFont("Plus Jakarta Sans", 14, QFont.Weight.Bold))
        l.addWidget(t)

        sub = QLabel("To ensure you safely recorded your recovery phrase, please enter the requested words:")
        sub.setStyleSheet("color: #94a3b8; font-size: 12px;")
        l.addWidget(sub)

        self.quiz_form = QFormLayout()
        self.quiz_inputs = {}
        l.addLayout(self.quiz_form)

        btn_row = QHBoxLayout()
        btn_back = QPushButton("Back to Words")
        btn_back.setProperty("class", "btn-secondary")
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        btn_row.addWidget(btn_back)

        btn_verify = QPushButton("Confirm Words & Proceed")
        btn_verify.setProperty("class", "btn-primary")
        btn_verify.clicked.connect(self.verify_quiz_words)
        btn_row.addWidget(btn_verify)

        l.addLayout(btn_row)
        self.stack.addWidget(w)

    def init_password_screen(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(16)

        t = QLabel("Set Strong Wallet Password")
        t.setFont(QFont("Plus Jakarta Sans", 14, QFont.Weight.Bold))
        l.addWidget(t)

        sub = QLabel("This password encrypts your private keys locally using AES-256-GCM. It will be required to unlock and send transactions.")
        sub.setStyleSheet("color: #94a3b8; font-size: 12px;")
        l.addWidget(sub)

        f = QFormLayout()
        self.pass_inp = QLineEdit()
        self.pass_inp.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_inp.setPlaceholderText("Minimum 8 characters")
        self.pass_inp.textChanged.connect(self.check_password_strength)

        self.pass_conf = QLineEdit()
        self.pass_conf.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_conf.setPlaceholderText("Confirm password")

        f.addRow("Password:", self.pass_inp)
        f.addRow("Confirm Password:", self.pass_conf)
        l.addLayout(f)

        self.strength_lbl = QLabel("Password strength: Enter at least 8 characters")
        self.strength_lbl.setStyleSheet("font-size: 12px; color: #94a3b8;")
        l.addWidget(self.strength_lbl)

        btn_finish = QPushButton("Finalize Wallet Setup")
        btn_finish.setProperty("class", "btn-primary")
        btn_finish.clicked.connect(self.finalize_setup)
        l.addWidget(btn_finish)

        self.stack.addWidget(w)

    def go_to_create_seed(self):
        # Multi-Source Hybrid Entropy: OS CSPRNG + Nanosecond Timer + Process ID + SHA-256
        raw = os.urandom(32)
        nano = time.time_ns() if hasattr(time, 'time_ns') else int(time.time() * 1e9)
        pid = os.getpid()
        salt = f"WINEX_GUI_SALT_{nano}_{pid}".encode()
        mixed_entropy = hashlib.sha256(raw + salt).digest()[:16]
        self.generated_seed = mnemo.to_mnemonic(mixed_entropy)
        words = self.generated_seed.split()

        # Clear existing grid
        while self.seed_grid.count():
            item = self.seed_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for idx, word in enumerate(words):
            card = QFrame()
            card.setMinimumHeight(34)
            card.setStyleSheet("background: #0d1016; border: 1px solid #1c2230; border-radius: 4px; padding: 4px 8px;")
            cl = QHBoxLayout(card)
            cl.setContentsMargins(8, 4, 8, 4)
            cl.setSpacing(8)
            num = QLabel(f"{idx+1:02d}.")
            num.setStyleSheet("color: #64748b; font-weight: 700; font-family: 'JetBrains Mono'; font-size: 11px; border: none;")
            w_lbl = QLabel(word)
            w_lbl.setStyleSheet("color: #38bdf8; font-weight: 700; font-size: 12.5px; font-family: 'JetBrains Mono'; border: none;")
            cl.addWidget(num)
            cl.addWidget(w_lbl)
            cl.addStretch()
            self.seed_grid.addWidget(card, idx // 3, idx % 3)

        self.chk_saved.setChecked(False)
        self.btn_next_quiz.setEnabled(False)
        self.stack.setCurrentIndex(1)

    def go_to_import_seed(self):
        txt, ok = QInputDialog.getMultiLineText(
            self, "Import Existing Seed",
            "Enter your 12-word recovery phrase (separated by spaces):"
        )
        if ok and txt:
            cleaned = " ".join(txt.strip().split())
            if len(cleaned.split()) != 12:
                QMessageBox.warning(self, "Invalid Seed", "Recovery phrase must contain exactly 12 words.")
                return
            if not mnemo.check(cleaned):
                QMessageBox.warning(self, "Invalid Checksum", "The entered words do not form a valid BIP-39 mnemonic phrase.")
                return
            self.generated_seed = cleaned
            # Skip quiz when importing known seed, go directly to password
            self.stack.setCurrentIndex(3)

    def copy_generated_seed(self):
        if self.generated_seed:
            QApplication.clipboard().setText(self.generated_seed)
            self.btn_copy_seed.setText("✓ Words Copied!")
            QTimer.singleShot(2000, lambda: self.btn_copy_seed.setText("📋 Copy Words"))

    def setup_and_go_quiz(self):
        words = self.generated_seed.split()
        import random
        # Pick 3 random distinct indices (1-indexed for display)
        self.quiz_indices = sorted(random.sample(range(1, 13), 3))

        # Clear form
        while self.quiz_form.count():
            item = self.quiz_form.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.quiz_inputs.clear()

        for idx in self.quiz_indices:
            inp = QLineEdit()
            inp.setPlaceholderText(f"Type Word #{idx}")
            self.quiz_inputs[idx] = inp
            lbl = QLabel(f"Word #{idx}:")
            lbl.setStyleSheet("font-weight: 700; font-family: 'JetBrains Mono';")
            self.quiz_form.addRow(lbl, inp)

        self.stack.setCurrentIndex(2)

    def verify_quiz_words(self):
        words = self.generated_seed.split()
        for idx in self.quiz_indices:
            inp_val = self.quiz_inputs[idx].text().strip().lower()
            expected = words[idx - 1].lower()
            if inp_val != expected:
                QMessageBox.warning(self, "Word Mismatch", f"Word #{idx} does not match your backup. Please check your written phrase and try again.")
                return
        # Quiz passed
        self.stack.setCurrentIndex(3)

    def check_password_strength(self, pwd: str):
        if len(pwd) < 8:
            self.strength_lbl.setText("Password strength: Too short (min 8 chars)")
            self.strength_lbl.setStyleSheet("font-size: 12px; color: #f87171;")
        elif any(c.isdigit() for c in pwd) and any(not c.isalnum() for c in pwd):
            self.strength_lbl.setText("Password strength: Strong")
            self.strength_lbl.setStyleSheet("font-size: 12px; color: #10b981;")
        else:
            self.strength_lbl.setText("Password strength: Moderate (add symbols and numbers)")
            self.strength_lbl.setStyleSheet("font-size: 12px; color: #fbbf24;")

    def finalize_setup(self):
        p1 = self.pass_inp.text()
        p2 = self.pass_conf.text()
        if len(p1) < 8:
            QMessageBox.warning(self, "Password Too Short", "Please enter a password with at least 8 characters.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return

        w_data = derive_wallet_from_seed(self.generated_seed)
        self.result_wallet_data = w_data
        self.result_password = p1
        self.accept()

# ==================== TWO-STAGE TRANSACTION CONFIRMATION DIALOG ====================

class TwoStageConfirmDialog(QDialog):
    def __init__(self, recipient: str, amount: float, fee: float, balance_after: float, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Review & Authorize Transaction")
        self.setFixedSize(460, 400)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        l = QVBoxLayout(self)
        l.setContentsMargins(16, 14, 16, 14)
        l.setSpacing(18)

        t = QLabel("Broadcast Transaction Authorization")
        t.setStyleSheet("font-size: 13px; font-weight: 700;")
        l.addWidget(t)

        card = QFrame()
        card.setProperty("class", "card")
        cl = QVBoxLayout(card)
        cl.setSpacing(8)
        cl.setContentsMargins(12, 10, 12, 10)

        # Recipient highlighted
        first6 = recipient[:6]
        mid = recipient[6:-6]
        last6 = recipient[-6:]

        recip_lbl = QLabel("Recipient Address:")
        recip_lbl.setStyleSheet("font-size: 11.5px; color: #8c96a8; font-weight: 600;")
        cl.addWidget(recip_lbl)

        recip_formatted = QLabel(f'<span style="color:#4b85e8; font-weight:700;">{first6}</span>'
                                f'<span style="color:#8c96a8;">{mid}</span>'
                                f'<span style="color:#4b85e8; font-weight:700;">{last6}</span>')
        recip_formatted.setFont(QFont("JetBrains Mono", 11))
        recip_formatted.setTextFormat(Qt.TextFormat.RichText)
        cl.addWidget(recip_formatted)

        # Anti-Clipboard Poisoning Protection
        clip_warn = QLabel(f"Verify prefix (<b>{first6}</b>) and suffix (<b>{last6}</b>) match destination.")
        clip_warn.setStyleSheet("background: #0d1016; border: 1px solid #1c2230; border-radius: 2px; padding: 6px 8px; color: #8c96a8; font-size: 11px;")
        clip_warn.setWordWrap(True)
        cl.addWidget(clip_warn)

        # Amount Row
        amt_box = QVBoxLayout()
        amt_box.addWidget(QLabel("Amount:"))
        amt_val = QLabel(f"{amount:.4f} WNX")
        amt_val.setFont(QFont("JetBrains Mono", 13, QFont.Weight.Bold))
        amt_val.setStyleSheet("color: #26a269; font-variant-numeric: tabular-nums;")
        amt_box.addWidget(amt_val)
        cl.addLayout(amt_box)

        bal_lbl = QLabel(f"Remaining Balance: {balance_after:.4f} WNX")
        bal_lbl.setStyleSheet("color: #8c96a8; font-size: 11.5px; font-variant-numeric: tabular-nums;")
        cl.addWidget(bal_lbl)

        l.addWidget(card)

        if amount >= 50.0:
            warn = QLabel("Notice: On-chain transactions are irreversible once confirmed.")
            warn.setStyleSheet("color: #cd9309; font-size: 11px; font-weight: 600;")
            warn.setWordWrap(True)
            l.addWidget(warn)

        # Password / PIN authorization
        pass_lbl = QLabel("Keystore Password:")
        pass_lbl.setStyleSheet("font-weight: 600; font-size: 11.5px; margin-top: 4px;")
        self.pass_inp = QLineEdit()
        self.pass_inp.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_inp.setPlaceholderText("Password")
        l.addWidget(pass_lbl)
        l.addWidget(self.pass_inp)

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setProperty("class", "btn-secondary")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_send = QPushButton("Confirm & Sign Broadcast")
        btn_send.setProperty("class", "btn-primary")
        btn_send.clicked.connect(self.accept)
        btn_row.addWidget(btn_send)

        l.addLayout(btn_row)

    def get_password(self) -> str:
        return self.pass_inp.text()

# ==================== ELECTRUM TOOLS: SIGN & VERIFY MESSAGE ====================

class SignVerifyDialog(QDialog):
    def __init__(self, wallet_data: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sign & Verify Message - Electrum SECP256k1")
        self.setFixedSize(520, 420)
        self.wallet_data = wallet_data or {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)

        title = QLabel("Cryptographic Message Utility")
        title.setFont(QFont("Plus Jakarta Sans", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        tab_row = QHBoxLayout()
        self.btn_sign_tab = QPushButton("Sign Message")
        self.btn_sign_tab.setProperty("class", "btn-primary")
        self.btn_sign_tab.clicked.connect(lambda: self.switch_sv_tab(0))
        self.btn_verify_tab = QPushButton("Verify Message")
        self.btn_verify_tab.setProperty("class", "btn-secondary")
        self.btn_verify_tab.clicked.connect(lambda: self.switch_sv_tab(1))
        tab_row.addWidget(self.btn_sign_tab)
        tab_row.addWidget(self.btn_verify_tab)
        layout.addLayout(tab_row)

        self.sv_stack = QStackedWidget()

        # Sign Tab
        sign_pane = QWidget()
        sl = QVBoxLayout(sign_pane)
        sl.setContentsMargins(0, 10, 0, 0)
        sl.setSpacing(10)

        sl.addWidget(QLabel("Message to sign:"))
        self.sign_msg_inp = QTextEdit()
        self.sign_msg_inp.setPlaceholderText("Enter arbitrary message to sign with your SECP256k1 key...")
        self.sign_msg_inp.setMaximumHeight(85)
        sl.addWidget(self.sign_msg_inp)

        btn_do_sign = QPushButton("Generate Cryptographic Signature")
        btn_do_sign.setProperty("class", "btn-primary")
        btn_do_sign.clicked.connect(self.do_sign)
        sl.addWidget(btn_do_sign)

        sl.addWidget(QLabel("Generated SECP256k1 Signature:"))
        self.sign_sig_out = QLineEdit()
        self.sign_sig_out.setReadOnly(True)
        self.sign_sig_out.setFont(QFont("JetBrains Mono", 11))
        sl.addWidget(self.sign_sig_out)

        self.sv_stack.addWidget(sign_pane)

        # Verify Tab
        verify_pane = QWidget()
        vl = QVBoxLayout(verify_pane)
        vl.setContentsMargins(0, 10, 0, 0)
        vl.setSpacing(8)

        vl.addWidget(QLabel("Signer Address (WNX...):"))
        self.ver_addr_inp = QLineEdit()
        self.ver_addr_inp.setPlaceholderText("WNX...")
        vl.addWidget(self.ver_addr_inp)

        vl.addWidget(QLabel("Signer Public Key (Hex):"))
        self.ver_pub_inp = QLineEdit()
        self.ver_pub_inp.setPlaceholderText("64-byte hex public key...")
        vl.addWidget(self.ver_pub_inp)

        vl.addWidget(QLabel("Signature (Hex):"))
        self.ver_sig_inp = QLineEdit()
        self.ver_sig_inp.setPlaceholderText("Signature hex...")
        vl.addWidget(self.ver_sig_inp)

        vl.addWidget(QLabel("Original Message:"))
        self.ver_msg_inp = QTextEdit()
        self.ver_msg_inp.setMaximumHeight(65)
        self.ver_msg_inp.setPlaceholderText("Original text that was signed...")
        vl.addWidget(self.ver_msg_inp)

        btn_do_verify = QPushButton("Verify Signature")
        btn_do_verify.setProperty("class", "btn-primary")
        btn_do_verify.clicked.connect(self.do_verify)
        vl.addWidget(btn_do_verify)

        self.ver_status_lbl = QLabel("")
        self.ver_status_lbl.setFont(QFont("Plus Jakarta Sans", 12, QFont.Weight.Bold))
        vl.addWidget(self.ver_status_lbl)

        self.sv_stack.addWidget(verify_pane)
        layout.addWidget(self.sv_stack)

    def switch_sv_tab(self, idx: int):
        self.sv_stack.setCurrentIndex(idx)
        if idx == 0:
            self.btn_sign_tab.setProperty("class", "btn-primary")
            self.btn_verify_tab.setProperty("class", "btn-secondary")
        else:
            self.btn_sign_tab.setProperty("class", "btn-secondary")
            self.btn_verify_tab.setProperty("class", "btn-primary")
        self.btn_sign_tab.style().unpolish(self.btn_sign_tab)
        self.btn_sign_tab.style().polish(self.btn_sign_tab)
        self.btn_verify_tab.style().unpolish(self.btn_verify_tab)
        self.btn_verify_tab.style().polish(self.btn_verify_tab)

    def do_sign(self):
        text = self.sign_msg_inp.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Empty Message", "Please enter a message to sign.")
            return
        priv = self.wallet_data.get("private_key", "")
        if not priv:
            QMessageBox.warning(self, "Key Unavailable", "Wallet private key is not accessible.")
            return
        try:
            sig = sign_transaction(priv, text)
            self.sign_sig_out.setText(sig)
        except Exception as e:
            QMessageBox.critical(self, "Signing Error", f"Could not sign message: {e}")

    def do_verify(self):
        addr = self.ver_addr_inp.text().strip()
        pub = self.ver_pub_inp.text().strip()
        sig = self.ver_sig_inp.text().strip()
        msg = self.ver_msg_inp.toPlainText().strip()

        if not pub or not sig or not msg:
            QMessageBox.warning(self, "Missing Fields", "Public key, signature, and message are required.")
            return

        try:
            if addr:
                pub_bytes = bytes.fromhex(pub)
                calc_addr = "WNX" + hashlib.sha256(pub_bytes).hexdigest()[:32].upper()
                if calc_addr != addr:
                    self.ver_status_lbl.setText(f"Address Mismatch! Derived: {calc_addr}")
                    self.ver_status_lbl.setStyleSheet("color: #f43f5e;")
                    return

            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub), curve=ecdsa.SECP256k1)
            try:
                valid = vk.verify(bytes.fromhex(sig), msg.encode('utf-8'), hashfunc=hashlib.sha256)
            except Exception:
                valid = vk.verify(bytes.fromhex(sig), msg.encode('utf-8'), hashfunc=hashlib.sha1)
            if valid:
                self.ver_status_lbl.setText("Valid Signature (SECP256k1 verified)")
                self.ver_status_lbl.setStyleSheet("color: #10b981;")
            else:
                self.ver_status_lbl.setText("Invalid Signature")
                self.ver_status_lbl.setStyleSheet("color: #f43f5e;")
        except Exception as e:
            self.ver_status_lbl.setText(f"Verification Failed: {e}")
            self.ver_status_lbl.setStyleSheet("color: #f43f5e;")

# ==================== COLD STORAGE / OFFLINE SIGNING DIALOG ====================

class ColdStorageDialog(QDialog):
    def __init__(self, wallet_data: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Electrum Cold Storage & Offline Signer")
        self.setFixedSize(520, 440)
        self.wallet_data = wallet_data

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)

        t = QLabel("Electrum Cold Storage & Offline Signing")
        t.setFont(QFont("Plus Jakarta Sans", 14, QFont.Weight.Bold))
        layout.addWidget(t)

        sub = QLabel("Air-gapped transaction lifecycle: Create unsigned tx online -> Sign on isolated offline computer -> Broadcast.")
        sub.setStyleSheet("color: #94a3b8; font-size: 12px;")
        sub.setWordWrap(True)
        layout.addWidget(sub)

        # Tab buttons
        tab_row = QHBoxLayout()
        self.btn_t1 = QPushButton("1. Create Unsigned")
        self.btn_t2 = QPushButton("2. Sign Offline (Air-Gapped)")
        self.btn_t3 = QPushButton("3. Broadcast Signed")
        for b in [self.btn_t1, self.btn_t2, self.btn_t3]:
            b.setProperty("class", "btn-secondary")
            tab_row.addWidget(b)
        layout.addLayout(tab_row)

        self.cs_stack = QStackedWidget()

        # Pane 1: Create Unsigned
        p1 = QWidget()
        l1 = QVBoxLayout(p1)
        l1.setSpacing(10)
        l1.addWidget(QLabel("Recipient Address:"))
        self.cs_recip_inp = QLineEdit()
        self.cs_recip_inp.setPlaceholderText("WNX...")
        l1.addWidget(self.cs_recip_inp)

        l1.addWidget(QLabel("Amount (WNX):"))
        self.cs_amt_inp = QDoubleSpinBox()
        self.cs_amt_inp.setRange(0.00000001, 100000000)
        self.cs_amt_inp.setDecimals(8)
        l1.addWidget(self.cs_amt_inp)

        btn_gen = QPushButton("Generate Unsigned Payload")
        btn_gen.setProperty("class", "btn-primary")
        btn_gen.clicked.connect(self.generate_unsigned)
        l1.addWidget(btn_gen)

        self.cs_unsigned_out = QTextEdit()
        self.cs_unsigned_out.setPlaceholderText("Unsigned JSON payload will appear here. Copy and transport via USB/QR...")
        self.cs_unsigned_out.setReadOnly(True)
        l1.addWidget(self.cs_unsigned_out)
        self.cs_stack.addWidget(p1)

        # Pane 2: Sign Offline
        p2 = QWidget()
        l2 = QVBoxLayout(p2)
        l2.setSpacing(10)
        l2.addWidget(QLabel("Paste Unsigned Transaction Payload:"))
        self.cs_unsigned_in = QTextEdit()
        self.cs_unsigned_in.setPlaceholderText("Paste unsigned JSON payload here...")
        l2.addWidget(self.cs_unsigned_in)

        l2.addWidget(QLabel("Wallet Password (to authorize private key):"))
        self.cs_pass_inp = QLineEdit()
        self.cs_pass_inp.setEchoMode(QLineEdit.EchoMode.Password)
        self.cs_pass_inp.setPlaceholderText("Enter password...")
        l2.addWidget(self.cs_pass_inp)

        btn_sign = QPushButton("Sign Offline (RFC 6979 SECP256k1)")
        btn_sign.setProperty("class", "btn-primary")
        btn_sign.clicked.connect(self.sign_offline)
        l2.addWidget(btn_sign)

        self.cs_signed_out = QTextEdit()
        self.cs_signed_out.setPlaceholderText("Cryptographically signed payload will appear here...")
        self.cs_signed_out.setReadOnly(True)
        l2.addWidget(self.cs_signed_out)
        self.cs_stack.addWidget(p2)

        # Pane 3: Broadcast
        p3 = QWidget()
        l3 = QVBoxLayout(p3)
        l3.setSpacing(10)
        l3.addWidget(QLabel("Paste Signed Payload to Broadcast:"))
        self.cs_signed_in = QTextEdit()
        self.cs_signed_in.setPlaceholderText("Paste signed JSON payload here...")
        l3.addWidget(self.cs_signed_in)

        btn_bcast = QPushButton("Broadcast to Sovereign Network")
        btn_bcast.setProperty("class", "btn-primary")
        btn_bcast.clicked.connect(self.broadcast_offline)
        l3.addWidget(btn_bcast)
        l3.addStretch()
        self.cs_stack.addWidget(p3)

        layout.addWidget(self.cs_stack)

        self.btn_t1.clicked.connect(lambda: self.switch_cs_tab(0))
        self.btn_t2.clicked.connect(lambda: self.switch_cs_tab(1))
        self.btn_t3.clicked.connect(lambda: self.switch_cs_tab(2))
        self.switch_cs_tab(0)

    def switch_cs_tab(self, idx: int):
        self.cs_stack.setCurrentIndex(idx)
        for i, b in enumerate([self.btn_t1, self.btn_t2, self.btn_t3]):
            b.setProperty("class", "btn-primary" if i == idx else "btn-secondary")
            b.style().unpolish(b)
            b.style().polish(b)

    def generate_unsigned(self):
        recip = self.cs_recip_inp.text().strip()
        amt = self.cs_amt_inp.value()
        if not validate_address_format(recip):
            QMessageBox.warning(self, "Invalid Address", "Please enter a valid recipient address starting with WNX.")
            return
        if not self.wallet_data:
            QMessageBox.warning(self, "Error", "Wallet address unavailable.")
            return
        sender = self.wallet_data.get("address", "")
        payload = {
            "type": "WINEX_RAW_TX_V1",
            "sender": sender,
            "recipient": recip,
            "amount": amt,
            "fee": 0.0,
            "timestamp": int(time.time()),
            "public_key": self.wallet_data.get("public_key", "")
        }
        self.cs_unsigned_out.setText(json.dumps(payload, indent=2))

    def sign_offline(self):
        txt = self.cs_unsigned_in.toPlainText().strip()
        pwd = self.cs_pass_inp.text()
        if not txt or not pwd:
            QMessageBox.warning(self, "Missing Fields", "Please paste the payload and enter your password.")
            return
        try:
            payload = json.loads(txt)
            enc = load_encrypted_wallet_dict()
            dec = decrypt_wallet_data(enc, pwd)
            priv = dec["private_key"]
            pub = dec["public_key"]
            sender = payload["sender"]
            recip = payload["recipient"]
            amt = float(payload["amount"])
            ts = float(payload["timestamp"])
            msg = f"{sender}:{recip}:{amt:.4f}:0.0000:{ts:.4f}"
            sig = sign_transaction(priv, msg)
            del priv
            del dec
            import gc
            gc.collect()

            signed_payload = dict(payload)
            signed_payload["signature"] = sig
            signed_payload["public_key"] = pub
            self.cs_signed_out.setText(json.dumps(signed_payload, indent=2))
            QMessageBox.information(self, "Signed Offline", "Transaction successfully signed deterministically with SECP256k1 RFC 6979!")
        except Exception as e:
            QMessageBox.critical(self, "Signing Failed", f"Could not sign offline transaction: {e}")

    def broadcast_offline(self):
        txt = self.cs_signed_in.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "Empty", "Please paste the signed JSON payload.")
            return
        try:
            payload = json.loads(txt)
            sender = payload["sender"]
            recip = payload["recipient"]
            amt = float(payload["amount"])
            ts = float(payload["timestamp"])
            pub = payload["public_key"]
            sig = payload["signature"]

            if hasattr(self.parent(), 'api_request'):
                r = self.parent().api_request("POST", "api/tx/send", json={
                    "sender": sender,
                    "recipient": recip,
                    "amount": amt,
                    "fee": 0.0,
                    "timestamp": ts,
                    "public_key": pub,
                    "signature": sig
                })
                res = r.json()
                txid = res.get("tx_id", "Confirmed")
                QMessageBox.information(self, "Broadcast Successful", f"Transaction broadcast to sovereign network!\n\nTXID: {txid[:28]}...")
                self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Broadcast Error", f"Network broadcast failed: {e}")

class LocalChainResponse:
    def __init__(self, data: any, status_code: int = 200):
        self._data = data
        self.status_code = status_code

    def json(self):
        return self._data

# ==================== ASYNCHRONOUS NETWORK POLLER WORKER ====================

class NetworkPollerWorker(QThread):
    data_received = Signal(dict)

    def __init__(self, candidate_nodes: list, address: str, addresses_list: list = None, parent=None):
        super().__init__(parent)
        self.candidate_nodes = list(candidate_nodes)
        self.address = address
        self.addresses_list = list(addresses_list) if addresses_list else ([address] if address else [])
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        if not self._running:
            return
        result = {}
        balances_map = {}

        # 1. Poll Balances for all derived HD addresses
        for addr in self.addresses_list:
            if not addr:
                continue
            for node in self.candidate_nodes:
                if not self._running:
                    return
                try:
                    url = f"{node.rstrip('/')}/api/balance/{addr}"
                    r = requests.get(url, timeout=2.0)
                    if r.status_code == 200:
                        balances_map[addr] = float(r.json().get("balance", 0.0))
                        break
                except Exception:
                    pass

        if balances_map:
            result["balances_map"] = balances_map
            result["total_balance"] = sum(balances_map.values())
            result["balance"] = balances_map.get(self.address, sum(balances_map.values()))

        # 2. Poll Status (/api/state or /api/status)
        for node in self.candidate_nodes:
            if not self._running:
                return
            try:
                url = f"{node.rstrip('/')}/api/state"
                r = requests.get(url, timeout=2.0)
                if r.status_code == 200:
                    result["status"] = r.json()
                    break
                url2 = f"{node.rstrip('/')}/api/status"
                r2 = requests.get(url2, timeout=2.0)
                if r2.status_code == 200:
                    result["status"] = r2.json()
                    break
            except Exception:
                pass

        # 3. Poll Peers
        for node in self.candidate_nodes:
            if not self._running:
                return
            try:
                url = f"{node.rstrip('/')}/api/p2p/peers"
                r = requests.get(url, timeout=2.0)
                if r.status_code == 200:
                    result["peers"] = r.json().get("peers", [])
                    break
            except Exception:
                pass

        # 4. Poll Recent Blocks & Transactions
        for node in self.candidate_nodes:
            if not self._running:
                return
            try:
                url = f"{node.rstrip('/')}/api/chain?limit=15"
                r = requests.get(url, timeout=2.0)
                if r.status_code == 200:
                    data = r.json()
                    result["blocks"] = data.get("blocks", data) if isinstance(data, dict) else data
                    break
                url2 = f"{node.rstrip('/')}/api/blocks?limit=15"
                r2 = requests.get(url2, timeout=2.0)
                if r2.status_code == 200:
                    result["blocks"] = r2.json()
                    break
            except Exception:
                pass

        # 5. Local Sovereign Core Fallback (100% Autonomous if remote web/VDS is offline)
        if "balance" not in result or "status" not in result:
            try:
                import winex_core
                db_path = os.path.join(WALLET_DIR, "chain.db")
                if os.path.exists(db_path):
                    local_chain = winex_core.WinexBlockchain(db_path)
                    if "balance" not in result and self.address:
                        result["balance"] = local_chain.get_balance(self.address)
                    if "status" not in result:
                        h = local_chain.get_height()
                        result["status"] = {
                            "block_height": h,
                            "peer_count": 0,
                            "block_reward": winex_core.get_block_reward(h),
                            "mining_pool_available": local_chain.get_pool_remaining()
                        }
                    if "blocks" not in result:
                        result["blocks"] = local_chain.get_latest_blocks(10)
                    result["is_local_core"] = True
            except Exception:
                pass

        if result and self._running:
            self.data_received.emit(result)

# ==================== MAIN WALLET GUI WINDOW ====================

class WinexWalletApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WINEX Core Wallet")
        self.setMinimumSize(680, 325)
        self.resize(800, 365)
        self.setObjectName("WINEX_Wallet")
        if os.path.exists(LOGO_PATH):
            self.setWindowIcon(QIcon(LOGO_PATH))

        ensure_secure_permissions()

        # Electrum Cold Memory State: Always start locked on launch
        self.wallet_data = None
        self.unlocked_password = None
        self.is_locked = True
        self.failed_unlock_attempts = 0

        self.config = {
            "theme": "dark",
            "language": "en",
            "auto_lock_minutes": 15,
            "node_url": DEFAULT_NODE
        }
        self.load_config()
        self.active_node = self.config.get("node_url", DEFAULT_NODE)
        self.discovered_peers = []

        # Inactivity auto-lock timer
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self.on_auto_lock_timeout)
        self.reset_inactivity_timer()

        # Install event filter to detect user activity
        QApplication.instance().installEventFilter(self)

        self.init_ui()
        self.apply_theme(self.config["theme"])

        # Electrum Security Protocol: Cold-lock immediately upon launch
        if has_any_wallet_file():
            self.lock_wallet()
        else:
            QTimer.singleShot(100, self.check_wallet_state)

        # Background polling for balance & blocks (runs only when unlocked)
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.poll_network_data)
        self.poll_timer.start(5000)

    def closeEvent(self, event):
        # Electrum Zero-Retention & Instant Process Termination Protocol
        self.is_locked = True
        self.wallet_data = None
        self.unlocked_password = None
        if hasattr(self, 'inactivity_timer'):
            self.inactivity_timer.stop()
        if hasattr(self, 'poll_timer'):
            self.poll_timer.stop()
        if hasattr(self, 'poller_thread') and self.poller_thread:
            self.poller_thread.stop()
            self.poller_thread.wait(300)
        import gc
        gc.collect()
        event.accept()
        QApplication.instance().quit()
        os._exit(0)

    def toggle_theme_shortcut(self):
        curr = self.config.get("theme", "dark")
        nxt = "light" if curr == "dark" else "dark"
        self.config["theme"] = nxt
        self.apply_theme(nxt)
        self.save_config()
        if hasattr(self, 'theme_combo'):
            self.theme_combo.setCurrentIndex(0 if nxt == "dark" else 1)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress):
            if not self.is_locked:
                self.reset_inactivity_timer()
        return super().eventFilter(obj, event)

    def reset_inactivity_timer(self):
        mins = self.config.get("auto_lock_minutes", 15)
        if mins > 0:
            self.inactivity_timer.start(mins * 60 * 1000)
        else:
            self.inactivity_timer.stop()

    def on_auto_lock_timeout(self):
        if self.wallet_data and not self.is_locked:
            self.lock_wallet()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.config.update(json.load(f))
            except Exception:
                pass
        if self.config.get("node_url") in ("https://winexcoin.com", "http://winexcoin.com", ""):
            self.config["node_url"] = "http://127.0.0.1:8081"
            self.save_config()

    def save_config(self):
        ensure_secure_permissions()
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass

    def apply_theme(self, theme_name: str):
        if theme_name == "light":
            self.setStyleSheet(LIGHT_THEME_QSS)
        else:
            self.setStyleSheet(DARK_THEME_QSS)

    def get_candidate_nodes(self) -> list:
        configured = self.config.get("node_url", DEFAULT_NODE)
        nodes = [self.active_node] if hasattr(self, 'active_node') and self.active_node else [configured]
        for b in [configured] + BOOTSTRAP_NODES:
            if b and b not in nodes:
                nodes.append(b)
        if hasattr(self, 'discovered_peers'):
            for p in self.discovered_peers:
                p_url = f"http://{p}" if not p.startswith("http") else p
                if p_url not in nodes:
                    nodes.append(p_url)
        return nodes

    def api_request(self, method: str, endpoint: str, **kwargs) -> any:
        nodes = self.get_candidate_nodes()
        last_exc = None
        for node in nodes:
            url = f"{node.rstrip('/')}/{endpoint.lstrip('/')}"
            try:
                kwargs.setdefault("timeout", 4)
                r = requests.request(method, url, **kwargs)
                if r.status_code in (200, 201):
                    if not hasattr(self, 'active_node') or node != self.active_node:
                        self.active_node = node
                        clean_disp = node.replace("https://", "").replace("http://", "")
                        if hasattr(self, 'sb_node_lbl'):
                            self.sb_node_lbl.setText("Sovereign P2P Mesh")
                            self.sb_node_lbl.setToolTip(f"Active P2P Peer: {clean_disp}")
                        if hasattr(self, 'net_pill'):
                            self.net_pill.setText("Sovereign Mesh")
                            self.net_pill.setToolTip(f"Active P2P Peer: {clean_disp}")
                    return r
            except Exception as e:
                last_exc = e
                continue

        # Sovereign Local Fallback: If all remote network nodes are unreachable, use local chain directly
        try:
            import winex_core
            db_path = os.path.join(WALLET_DIR, "chain.db")
            local_chain = winex_core.WinexBlockchain(db_path)
            if hasattr(self, 'sb_node_lbl'):
                self.sb_node_lbl.setText("Sovereign Local Core (Autonomous)")
                self.sb_node_lbl.setToolTip("Autonomous Mode: Running directly against local ledger")
            if hasattr(self, 'net_pill'):
                self.net_pill.setText("Sovereign Core")
                self.net_pill.setToolTip("Autonomous Local Ledger")

            clean_endpoint = endpoint.strip("/")
            if clean_endpoint.startswith("api/balance/"):
                addr = clean_endpoint.split("/")[-1]
                bal = local_chain.get_balance(addr)
                return LocalChainResponse({"address": addr, "balance": bal})
            elif clean_endpoint == "api/status":
                height = local_chain.get_height()
                reward = winex_core.get_block_reward(height)
                pool = local_chain.get_pool_remaining()
                return LocalChainResponse({
                    "block_height": height,
                    "block_reward": reward,
                    "mining_pool_available": pool,
                    "peer_count": 0,
                    "network": "WINEX Sovereign Core"
                })
            elif clean_endpoint == "api/p2p/peers":
                return LocalChainResponse({"peers": local_chain.get_peers()})
            elif clean_endpoint.startswith("api/blocks"):
                blocks = local_chain.get_latest_blocks(10)
                return LocalChainResponse(blocks)
            elif clean_endpoint in ("api/tx/send", "api/transaction/send"):
                tx_data = kwargs.get("json", {})
                success, txid = local_chain.add_transaction_to_mempool(tx_data)
                if success:
                    return LocalChainResponse({"status": "success", "txid": txid})
                else:
                    return LocalChainResponse({"status": "error", "message": txid}, status_code=400)
        except Exception:
            pass

        raise last_exc or Exception("All decentralized gateway nodes unreachable and local fallback failed")

    def open_cold_storage_dialog(self):
        if not self.wallet_data or self.is_locked:
            QMessageBox.warning(self, "Vault Locked", "Please unlock your wallet first.")
            return
        dlg = ColdStorageDialog(self.wallet_data, self)
        dlg.exec()

    def init_ui(self):
        # Electrum Native Menu Bar
        mb = self.menuBar()

        # File Menu
        file_menu = mb.addMenu("&File")
        act_new_restore = file_menu.addAction("New / Restore Keystore...")
        act_new_restore.triggered.connect(self.restore_from_seed_unlock_screen)
        act_lock = file_menu.addAction("Lock Keystore")
        act_lock.setShortcut("Ctrl+L")
        act_lock.triggered.connect(self.lock_wallet)
        file_menu.addSeparator()
        act_quit = file_menu.addAction("Quit")
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)

        # Wallet Menu
        wallet_menu = mb.addMenu("&Wallet")
        act_new_addr = wallet_menu.addAction("New HD Receiving Address")
        act_new_addr.setShortcut("Ctrl+N")
        act_new_addr.triggered.connect(self.generate_new_hd_address)
        wallet_menu.addSeparator()
        act_info = wallet_menu.addAction("Keystore Details")
        act_info.triggered.connect(self.show_wallet_info_dialog)
        act_seed = wallet_menu.addAction("Seed Phrase Backup...")
        act_seed.triggered.connect(self.reveal_seed_phrase)
        act_pubk = wallet_menu.addAction("Copy Master Public Key")
        act_pubk.triggered.connect(self.copy_pubkey)

        # Tools Menu
        tools_menu = mb.addMenu("&Tools")
        act_sv = tools_menu.addAction("Sign / Verify Message")
        act_sv.setShortcut("Ctrl+M")
        act_sv.triggered.connect(self.open_sign_verify_dialog)
        act_cold = tools_menu.addAction("Offline Transaction Signer")
        act_cold.setShortcut("Ctrl+O")
        act_cold.triggered.connect(self.open_cold_storage_dialog)
        tools_menu.addSeparator()
        act_cli = tools_menu.addAction("RPC Console")
        act_cli.setShortcut("Ctrl+T")
        act_cli.triggered.connect(lambda: self.switch_page(4))
        act_net = tools_menu.addAction("Network & Peers")
        act_net.triggered.connect(lambda: self.switch_page(5))
        act_pref = tools_menu.addAction("Preferences")
        act_pref.triggered.connect(lambda: self.switch_page(6))

        # View Menu
        view_menu = mb.addMenu("&View")
        act_hide_bal = view_menu.addAction("Mask / Unmask Balances")
        act_hide_bal.setShortcut("Ctrl+H")
        act_hide_bal.triggered.connect(self.toggle_hide_balance)
        view_menu.addSeparator()
        act_theme_toggle = view_menu.addAction("Switch Dark / Light Polarity")
        act_theme_toggle.triggered.connect(self.toggle_theme_shortcut)

        # Help Menu
        help_menu = mb.addMenu("&Help")
        help_menu.addAction("Protocol Specification", lambda: self.switch_page(7))

        # Electrum Bottom Status Bar: Balance on Left, Node/Height/Cipher on Right
        self.sb = self.statusBar()
        self.sb.setSizeGripEnabled(True)

        self.bal_display = QLabel("Balance: 0.0000 WNX")
        self.bal_display.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        self.bal_display.setStyleSheet("color: #ededf0; padding: 0 10px;")
        self.sb.addWidget(self.bal_display)

        self.eye_btn = QPushButton("Hide")
        self.eye_btn.setFixedHeight(20)
        self.eye_btn.setStyleSheet("padding: 0px 6px; min-height: 18px; font-size: 10.5px; background: transparent; border: 1px solid #1e1e24; color: #8e8e96;")
        self.eye_btn.clicked.connect(self.toggle_hide_balance)
        self.sb.addWidget(self.eye_btn)

        clean_disp = self.active_node.replace("https://", "").replace("http://", "")
        self.sb_node_lbl = QLabel("Node: P2P Mesh (:8081)")
        self.sb_node_lbl.setStyleSheet("color: #22c55e; padding: 0 10px; border-left: 1px solid #1e1e24;")
        self.sb_node_lbl.setToolTip(f"Active Peer: {clean_disp}")

        self.sb_height_lbl = QLabel("Height: 0")
        self.sb_height_lbl.setStyleSheet("color: #d4d4dc; padding: 0 10px; border-left: 1px solid #1e1e24;")

        self.sb_vault_lbl = QLabel("AES-256-GCM")
        self.sb_vault_lbl.setStyleSheet("color: #8e8e96; padding: 0 10px; border-left: 1px solid #1e1e24;")

        self.sb.addPermanentWidget(self.sb_node_lbl)
        self.sb.addPermanentWidget(self.sb_height_lbl)
        self.sb.addPermanentWidget(self.sb_vault_lbl)

        # Central Stack: [0] Tab Widget (unlocked), [1] Locked Screen (locked)
        self.central_stack = QStackedWidget()
        self.setCentralWidget(self.central_stack)

        # Electrum Horizontal Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.addTab(self.init_history_page(), "History")
        self.tab_widget.addTab(self.init_send_page(), "Send")
        self.tab_widget.addTab(self.init_receive_page(), "Receive")
        self.tab_widget.addTab(self.init_addresses_page(), "Addresses")
        self.tab_widget.addTab(self.init_console_page(), "Console")
        self.tab_widget.addTab(self.init_network_page(), "Network")
        self.tab_widget.addTab(self.init_settings_page(), "Preferences")
        self.tab_widget.addTab(self.init_about_page(), "Specification")

        self.central_stack.addWidget(self.tab_widget)

        self.init_locked_page()
        self.central_stack.addWidget(self.locked_page)

    def switch_page(self, index: int, active_btn=None):
        if self.is_locked:
            return
        if hasattr(self, 'tab_widget'):
            self.tab_widget.setCurrentIndex(index)

    # ==================== PAGE 0: HISTORY (ELECTRUM LEDGER TABLE) ====================
    def init_history_page(self) -> QWidget:
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(6, 6, 6, 6)
        l.setSpacing(5)

        # Compact Toolbar Row (No Hero Card, No Eyebrow Kicker)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self.tx_search = QLineEdit()
        self.tx_search.setPlaceholderText("Filter ledger by block height, hash, or address...")
        self.tx_search.textChanged.connect(self.filter_transactions)
        toolbar.addWidget(self.tx_search, 1)

        btn_refresh = QPushButton("Sync Ledger")
        btn_refresh.setProperty("class", "btn-secondary")
        btn_refresh.clicked.connect(self.poll_network_data)
        toolbar.addWidget(btn_refresh)

        l.addLayout(toolbar)

        # Full-Bleed Dense Ledger Table
        self.hist_table = QTableWidget(0, 4)
        self.hist_table.setAlternatingRowColors(True)
        self.hist_table.verticalHeader().setVisible(False)
        self.hist_table.verticalHeader().setDefaultSectionSize(24)
        self.hist_table.setHorizontalHeaderLabels(["State", "Block / Digest Reference", "Subsidy / Value", "Timestamp"])
        self.hist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.hist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.hist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.hist_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.hist_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        l.addWidget(self.hist_table, 1)
        self.recent_table = self.hist_table

        self.balance_hidden = False
        return page

    def filter_transactions(self, query: str):
        q = query.strip().lower()
        for r in range(self.hist_table.rowCount()):
            match = False
            for c in range(self.hist_table.columnCount()):
                item = self.hist_table.item(r, c)
                if item and q in item.text().lower():
                    match = True
                    break
            self.hist_table.setRowHidden(r, not match)

    def toggle_hide_balance(self):
        self.balance_hidden = not self.balance_hidden
        if self.balance_hidden:
            self.bal_display.setText("Balance: ******** WNX")
            self.eye_btn.setText("Show")
        else:
            self.eye_btn.setText("Hide")
            self.poll_network_data()

    # ==================== PAGE 1: SEND (ELECTRUM FORM GRID) ====================
    def init_send_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(6)

        form_frame = QFrame()
        form_frame.setProperty("class", "card")
        grid = QGridLayout(form_frame)
        grid.setContentsMargins(10, 8, 10, 8)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)

        # Row 0: From Account
        lbl_from = QLabel("From Account")
        lbl_from.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.send_from_combo = QComboBox()
        self.send_from_combo.setFont(QFont("JetBrains Mono", 11))
        self.send_from_combo.currentIndexChanged.connect(self.on_send_from_changed)
        grid.addWidget(lbl_from, 0, 0)
        grid.addWidget(self.send_from_combo, 0, 1, 1, 3)

        # Row 1: Pay To
        lbl_payto = QLabel("Pay to")
        lbl_payto.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.send_recip_inp = QLineEdit()
        self.send_recip_inp.setFont(QFont("JetBrains Mono", 11))
        self.send_recip_inp.setPlaceholderText("WNX... (35-character destination address)")
        self.send_recip_inp.textChanged.connect(self.on_recipient_text_changed)

        btn_paste = QPushButton("Paste")
        btn_paste.setProperty("class", "btn-secondary")
        btn_paste.clicked.connect(lambda: self.send_recip_inp.setText(QApplication.clipboard().text().strip()))
        grid.addWidget(lbl_payto, 1, 0)
        grid.addWidget(self.send_recip_inp, 1, 1, 1, 2)
        grid.addWidget(btn_paste, 1, 3)

        # Row 2: Description
        lbl_desc = QLabel("Description")
        lbl_desc.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.send_desc_inp = QLineEdit()
        self.send_desc_inp.setPlaceholderText("Local ledger memo (not broadcast on-chain)")
        grid.addWidget(lbl_desc, 2, 0)
        grid.addWidget(self.send_desc_inp, 2, 1, 1, 3)

        # Row 3: Amount + Max + Fee
        lbl_amt = QLabel("Amount")
        lbl_amt.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.send_amt_inp = QDoubleSpinBox()
        self.send_amt_inp.setFont(QFont("JetBrains Mono", 11))
        self.send_amt_inp.setRange(0.00000001, 10_000_000.0)
        self.send_amt_inp.setDecimals(8)
        self.send_amt_inp.setSingleStep(0.00000001)
        self.send_amt_inp.setSuffix(" WNX")

        self.btn_max = QPushButton("Max")
        self.btn_max.setProperty("class", "btn-secondary")
        self.btn_max.clicked.connect(self.use_max_balance)

        lbl_fee_info = QLabel("Fee: 0.0000 WNX (Layer-1 Zero-Fee Settlement)")
        lbl_fee_info.setFont(QFont("JetBrains Mono", 10.5))
        lbl_fee_info.setStyleSheet("color: #8e8e96;")

        grid.addWidget(lbl_amt, 3, 0)
        grid.addWidget(self.send_amt_inp, 3, 1)
        grid.addWidget(self.btn_max, 3, 2)
        grid.addWidget(lbl_fee_info, 3, 3)

        # Row 4: Validation status
        self.addr_val_lbl = QLabel("Enter a valid WNX destination address.")
        self.addr_val_lbl.setStyleSheet("color: #8e8e96; font-size: 11px;")
        grid.addWidget(self.addr_val_lbl, 4, 1, 1, 3)

        l.addWidget(form_frame)

        # Action Bar (Right-aligned Electrum pattern)
        act_bar = QHBoxLayout()
        act_bar.setSpacing(6)
        btn_clear = QPushButton("Clear")
        btn_clear.setProperty("class", "btn-secondary")
        btn_clear.clicked.connect(self.clear_send_form)

        btn_offline = QPushButton("Offline Signer...")
        btn_offline.setProperty("class", "btn-secondary")
        btn_offline.clicked.connect(self.open_cold_storage_dialog)

        btn_review = QPushButton("Pay / Broadcast...")
        btn_review.setProperty("class", "btn-primary")
        btn_review.clicked.connect(self.start_two_stage_send)

        act_bar.addStretch()
        act_bar.addWidget(btn_clear)
        act_bar.addWidget(btn_offline)
        act_bar.addWidget(btn_review)
        l.addLayout(act_bar)
        l.addStretch()
        return page

    def clear_send_form(self):
        self.send_recip_inp.clear()
        self.send_desc_inp.clear()
        self.send_amt_inp.setValue(0.00000001)
        self.addr_val_lbl.setText("Enter a valid WNX destination address.")
        self.addr_val_lbl.setStyleSheet("color: #8e8e96; font-size: 11px;")

    def on_recipient_text_changed(self, text: str):
        t = text.strip()
        if not t:
            self.addr_val_lbl.setText("Enter a valid WNX destination address.")
            self.addr_val_lbl.setStyleSheet("color: #8e8e96; font-size: 11px;")
        elif validate_address_format(t):
            self.addr_val_lbl.setText("Checksum valid: 32-hex SECP256k1 destination")
            self.addr_val_lbl.setStyleSheet("color: #22c55e; font-size: 11px;")
        else:
            self.addr_val_lbl.setText("Invalid format: address must start with WNX followed by 32 uppercase hex characters")
            self.addr_val_lbl.setStyleSheet("color: #ef4444; font-size: 11px;")

    def on_send_from_changed(self, idx: int):
        pass

    def get_selected_send_account(self) -> dict:
        if not self.wallet_data:
            return {}
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data.get("accounts", [])
        if hasattr(self, 'send_from_combo') and self.send_from_combo.count() > 0:
            sel_addr = self.send_from_combo.currentData()
            for acc in accounts:
                if acc.get("address") == sel_addr:
                    return acc
        return accounts[0] if accounts else {}

    def use_max_balance(self):
        if not self.wallet_data:
            return
        acc = self.get_selected_send_account()
        bal = float(acc.get("balance", self.wallet_data.get("balance", 0.0)))
        self.send_amt_inp.setValue(max(0.00000001, bal))

    def start_two_stage_send(self):
        recip = self.send_recip_inp.text().strip()
        amt = self.send_amt_inp.value()
        fee = 0.0

        if not validate_address_format(recip):
            QMessageBox.warning(self, "Invalid Address", "Please enter a valid WINEX address starting with WNX.")
            return

        if not self.wallet_data:
            QMessageBox.warning(self, "Wallet Not Ready", "Wallet data not loaded.")
            return

        send_acc = self.get_selected_send_account()
        cur_bal = float(send_acc.get("balance", self.wallet_data.get("balance", 0.0)))
        if amt > cur_bal:
            QMessageBox.warning(self, "Insufficient Balance", f"Amount ({amt:.4f} WNX) exceeds selected address balance ({cur_bal:,.4f} WNX).")
            return

        bal_after = cur_bal - amt

        dlg = TwoStageConfirmDialog(recip, amt, fee, bal_after, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            pwd = dlg.get_password()
            self.execute_signed_transaction(recip, amt, fee, pwd)

    def execute_signed_transaction(self, recip: str, amt: float, fee: float, password: str):
        try:
            enc = load_encrypted_wallet_dict()
            decrypted = decrypt_wallet_data(enc, password)
            send_acc = self.get_selected_send_account()
            target_addr = send_acc.get("address", decrypted["address"])
            priv_hex = decrypted["private_key"]
            pub_hex = decrypted["public_key"]
            sender_addr = decrypted["address"]
            for acc in decrypted.get("accounts", []):
                if acc.get("address") == target_addr:
                    priv_hex = acc["private_key"]
                    pub_hex = acc["public_key"]
                    sender_addr = acc["address"]
                    break
        except Exception:
            QMessageBox.critical(self, "Authentication Failed", "Incorrect wallet password. Transaction canceled.")
            return

        ts = time.time()
        tx_msg = f"{sender_addr}:{recip}:{amt:.4f}:{fee:.4f}:{ts:.4f}"
        sig = sign_transaction(priv_hex, tx_msg)

        del priv_hex
        del decrypted

        try:
            r = self.api_request("POST", "api/transaction/send", json={
                "sender": sender_addr,
                "recipient": recip,
                "amount": amt,
                "fee": 0.0,
                "timestamp": ts,
                "public_key": pub_hex,
                "signature": sig
            })

            res = r.json()
            tx_id = res.get("tx_id", "Confirmed")
            QMessageBox.information(self, "Transaction Broadcasted",
                                    f"Transaction signed and broadcast to the network.\n\nTXID: {tx_id[:32]}")
            self.clear_send_form()
            self.poll_network_data()
        except Exception as ex:
            QMessageBox.critical(self, "Broadcast Failed", f"Network broadcast failed across candidate nodes: {ex}")

    # ==================== PAGE 2: RECEIVE (ASYMMETRIC SPLIT LAYOUT) ====================
    def init_receive_page(self):
        page = QWidget()
        split = QHBoxLayout(page)
        split.setContentsMargins(8, 8, 8, 8)
        split.setSpacing(8)

        # Left Pane: Receiving Address Specification & Request Builder
        left_frame = QFrame()
        left_frame.setProperty("class", "card")
        lg = QGridLayout(left_frame)
        lg.setContentsMargins(10, 8, 10, 8)
        lg.setHorizontalSpacing(10)
        lg.setVerticalSpacing(6)

        lbl_acc = QLabel("Receiving Account")
        lbl_acc.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.recv_acc_combo = QComboBox()
        self.recv_acc_combo.setFont(QFont("JetBrains Mono", 11))
        self.recv_acc_combo.currentIndexChanged.connect(self.on_recv_account_Combo_changed)
        lg.addWidget(lbl_acc, 0, 0)
        lg.addWidget(self.recv_acc_combo, 0, 1, 1, 2)

        lbl_addr = QLabel("Receiving Address")
        lbl_addr.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.recv_addr_lbl = QLineEdit("Loading...")
        self.recv_addr_lbl.setReadOnly(True)
        self.recv_addr_lbl.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        self.recv_addr_lbl.setStyleSheet("color: #f4f4f6; background: #060608;")
        lg.addWidget(lbl_addr, 1, 0)
        lg.addWidget(self.recv_addr_lbl, 1, 1, 1, 2)

        lbl_path = QLabel("Derivation Path")
        lbl_path.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.recv_path_lbl = QLineEdit("m/44'/999'/0'/0/0")
        self.recv_path_lbl.setReadOnly(True)
        self.recv_path_lbl.setFont(QFont("JetBrains Mono", 10.5))
        self.recv_path_lbl.setStyleSheet("color: #8e8e96; background: #060608;")
        lg.addWidget(lbl_path, 2, 0)
        lg.addWidget(self.recv_path_lbl, 2, 1, 1, 2)

        lbl_uri = QLabel("Payment URI")
        lbl_uri.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.recv_uri_lbl = QLineEdit("winex:")
        self.recv_uri_lbl.setReadOnly(True)
        self.recv_uri_lbl.setFont(QFont("JetBrains Mono", 10.5))
        self.recv_uri_lbl.setStyleSheet("color: #d4d4dc; background: #060608;")
        lg.addWidget(lbl_uri, 3, 0)
        lg.addWidget(self.recv_uri_lbl, 3, 1, 1, 2)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.btn_copy_addr = QPushButton("Copy Address")
        self.btn_copy_addr.setProperty("class", "btn-primary")
        self.btn_copy_addr.clicked.connect(self.copy_address_to_clipboard)

        btn_copy_uri = QPushButton("Copy URI")
        btn_copy_uri.setProperty("class", "btn-secondary")
        btn_copy_uri.clicked.connect(lambda: QApplication.clipboard().setText(self.recv_uri_lbl.text()))

        btn_new_hd = QPushButton("+ New HD Address")
        btn_new_hd.setProperty("class", "btn-secondary")
        btn_new_hd.clicked.connect(self.generate_new_hd_address)

        btn_row.addWidget(self.btn_copy_addr)
        btn_row.addWidget(btn_copy_uri)
        btn_row.addWidget(btn_new_hd)
        btn_row.addStretch()
        lg.addLayout(btn_row, 4, 1, 1, 2)

        lg.setRowStretch(5, 1)
        split.addWidget(left_frame, 1)

        # Right Pane: Architectural QR Frame
        right_frame = QFrame()
        right_frame.setProperty("class", "card")
        right_frame.setFixedWidth(168)
        rl = QVBoxLayout(right_frame)
        rl.setContentsMargins(10, 10, 10, 10)
        rl.setSpacing(6)

        self.qr_label = QLabel()
        self.qr_label.setFixedSize(146, 146)
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setStyleSheet("background: #ffffff; border: 1px solid #222229; padding: 4px;")
        rl.addWidget(self.qr_label)

        qr_cap = QLabel("SECP256k1 / BIP-39")
        qr_cap.setFont(QFont("JetBrains Mono", 9.5))
        qr_cap.setStyleSheet("color: #8e8e96;")
        rl.addWidget(qr_cap)
        rl.addStretch()

        split.addWidget(right_frame)
        return page

    def on_recv_account_Combo_changed(self, idx: int):
        if not self.wallet_data or idx < 0:
            return
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data.get("accounts", [])
        if 0 <= idx < len(accounts):
            acc = accounts[idx]
            self.wallet_data["active_index"] = acc.get("index", idx)
            self.wallet_data["address"] = acc["address"]
            self.wallet_data["public_key"] = acc["public_key"]
            self.wallet_data["private_key"] = acc["private_key"]
            sync_miner_address_file(acc["address"])
            self.recv_addr_lbl.setText(acc["address"])
            if hasattr(self, 'recv_path_lbl'):
                self.recv_path_lbl.setText(acc.get("derivation", f"m/44'/999'/0'/0/{acc.get('index', idx)}"))
            if hasattr(self, 'recv_uri_lbl'):
                self.recv_uri_lbl.setText(f"winex:{acc['address']}")
            self.render_qr_code(acc["address"])
            self.persist_wallet_accounts()

    def copy_address_to_clipboard(self):
        if self.wallet_data and "address" in self.wallet_data:
            QApplication.clipboard().setText(self.wallet_data["address"])
            self.btn_copy_addr.setText("Copied")
            QTimer.singleShot(1500, lambda: self.btn_copy_addr.setText("Copy Address"))

    def render_qr_code(self, address: str):
        if hasattr(self, 'recv_uri_lbl'):
            self.recv_uri_lbl.setText(f"winex:{address}")
        qr = qrcode.QRCode(version=1, box_size=5, border=1)
        qr.add_data(f"winex:{address}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        pix = QPixmap()
        pix.loadFromData(buffer.getvalue())
        self.qr_label.setPixmap(pix.scaled(134, 134, Qt.AspectRatioMode.KeepAspectRatio))

    # ==================== PAGE 3: ADDRESSES (ELECTRUM HD TABLE) ====================
    def init_addresses_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(6, 6, 6, 6)
        l.setSpacing(5)

        # Compact Electrum Action Toolbar
        top_bar = QHBoxLayout()
        top_bar.setSpacing(6)

        btn_new_addr = QPushButton("+ New HD Address")
        btn_new_addr.setProperty("class", "btn-primary")
        btn_new_addr.clicked.connect(self.generate_new_hd_address)
        top_bar.addWidget(btn_new_addr)

        btn_set_active = QPushButton("Set Active Receiving")
        btn_set_active.setProperty("class", "btn-secondary")
        btn_set_active.clicked.connect(self.set_selected_address_active)
        top_bar.addWidget(btn_set_active)

        btn_copy_sel = QPushButton("Copy Address")
        btn_copy_sel.setProperty("class", "btn-secondary")
        btn_copy_sel.clicked.connect(self.copy_selected_table_address)
        top_bar.addWidget(btn_copy_sel)

        btn_label = QPushButton("Edit Label")
        btn_label.setProperty("class", "btn-secondary")
        btn_label.clicked.connect(self.edit_selected_address_label)
        top_bar.addWidget(btn_label)

        btn_scan = QPushButton("Scan & Recover Accounts")
        btn_scan.setProperty("class", "btn-secondary")
        btn_scan.clicked.connect(self.scan_and_recover_hd_accounts)
        top_bar.addWidget(btn_scan)

        top_bar.addStretch()
        l.addLayout(top_bar)

        self.addr_table = QTableWidget(0, 5)
        self.addr_table.setAlternatingRowColors(True)
        self.addr_table.verticalHeader().setVisible(False)
        self.addr_table.verticalHeader().setDefaultSectionSize(24)
        self.addr_table.setHorizontalHeaderLabels(["Index / Label", "WNX Address", "Derivation Path", "State", "Balance"])
        self.addr_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.addr_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.addr_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.addr_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.addr_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.addr_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.addr_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.addr_table.cellDoubleClicked.connect(self.on_address_row_double_clicked)
        self.addr_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.addr_table.customContextMenuRequested.connect(self.show_address_context_menu)
        l.addWidget(self.addr_table, 1)

        return page

    def show_address_context_menu(self, pos):
        item = self.addr_table.itemAt(pos)
        if not item or not self.wallet_data:
            return
        row = item.row()
        self.addr_table.selectRow(row)
        accounts = self.wallet_data.get("accounts", [])
        if row < 0 or row >= len(accounts):
            return
        acc = accounts[row]
        addr = acc.get("address", "")

        menu = QMenu(self)
        act_copy = menu.addAction("Copy WNX Address")
        act_copy.triggered.connect(lambda: QApplication.clipboard().setText(addr))

        act_active = menu.addAction("Set as Active Receiving Address")
        act_active.triggered.connect(self.set_selected_address_active)

        act_label = menu.addAction("Edit Label...")
        act_label.triggered.connect(self.edit_selected_address_label)

        act_qr = menu.addAction("Show QR Code")
        act_qr.triggered.connect(lambda: (self.set_selected_address_active(), self.switch_page(2)))

        menu.exec(self.addr_table.viewport().mapToGlobal(pos))

    def refresh_addresses_ui(self):
        if not self.wallet_data:
            return
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data.get("accounts", [])
        active_addr = self.wallet_data.get("address", "")

        if hasattr(self, 'addr_table'):
            self.addr_table.setRowCount(len(accounts))
            for row, acc in enumerate(accounts):
                idx = acc.get("index", row)
                lbl = acc.get("label", f"Sub-Address #{idx}")
                addr = acc.get("address", "")
                deriv = acc.get("derivation", f"m/44'/999'/0'/0/{idx}")
                bal = float(acc.get("balance", 0.0))
                is_active = (addr == active_addr)

                item_idx = QTableWidgetItem(f"#{idx}  {lbl}")
                item_addr = QTableWidgetItem(addr)
                item_addr.setFont(QFont("JetBrains Mono", 11))
                item_addr.setForeground(QColor("#ffffff" if is_active else "#d4d4dc"))

                item_deriv = QTableWidgetItem(deriv)
                item_deriv.setFont(QFont("JetBrains Mono", 10.5))

                item_status = QTableWidgetItem("Receiving" if is_active else "Derived")
                item_status.setForeground(QColor("#22c55e" if is_active else "#8e8e96"))

                item_bal = QTableWidgetItem(f"{bal:,.4f} WNX")
                item_bal.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
                if bal > 0:
                    item_bal.setForeground(QColor("#22c55e"))

                self.addr_table.setItem(row, 0, item_idx)
                self.addr_table.setItem(row, 1, item_addr)
                self.addr_table.setItem(row, 2, item_deriv)
                self.addr_table.setItem(row, 3, item_status)
                self.addr_table.setItem(row, 4, item_bal)

        for combo_attr in ('send_from_combo', 'recv_acc_combo'):
            if hasattr(self, combo_attr):
                combo = getattr(self, combo_attr)
                prev_addr = combo.currentData() or active_addr
                combo.blockSignals(True)
                combo.clear()
                sel_i = 0
                for i, acc in enumerate(accounts):
                    addr = acc.get("address", "")
                    lbl = acc.get("label", f"#{acc.get('index', i)}")
                    bal = float(acc.get("balance", 0.0))
                    short_a = f"{addr[:10]}...{addr[-6:]}" if len(addr) > 18 else addr
                    combo.addItem(f"#{acc.get('index', i)} {lbl} [{short_a}] — {bal:,.4f} WNX", addr)
                    if addr == prev_addr:
                        sel_i = i
                combo.setCurrentIndex(sel_i)
                combo.blockSignals(False)

    def persist_wallet_accounts(self):
        if not self.wallet_data or not self.unlocked_password:
            return
        try:
            enc = encrypt_wallet_data(self.wallet_data, self.unlocked_password)
            save_wallet_file_atomic(WALLET_FILE, enc)
        except Exception:
            pass

    def generate_new_hd_address(self):
        if not self.wallet_data or self.is_locked:
            QMessageBox.warning(self, "Vault Locked", "Please unlock your wallet first.")
            return
        ensure_wallet_accounts(self.wallet_data)
        seed = self.wallet_data.get("seed_phrase", "")
        if not seed:
            QMessageBox.warning(self, "Seed Unavailable", "Master seed phrase is not present in this vault.")
            return

        accounts = self.wallet_data["accounts"]
        next_idx = max([a.get("index", 0) for a in accounts] + [-1]) + 1
        default_lbl = f"Account #{next_idx}"
        lbl, ok = QInputDialog.getText(self, "New HD Address", f"Label for HD address #{next_idx}:", QLineEdit.EchoMode.Normal, default_lbl)
        if not ok:
            return
        lbl = lbl.strip() or default_lbl

        new_acc = derive_hd_account(seed, next_idx, lbl)
        accounts.append(new_acc)
        self.persist_wallet_accounts()
        self.refresh_addresses_ui()
        self.switch_page(3)
        self.poll_network_data()

    def scan_and_recover_hd_accounts(self):
        if not self.wallet_data or self.is_locked:
            QMessageBox.warning(self, "Vault Locked", "Please unlock your wallet first.")
            return
        ensure_wallet_accounts(self.wallet_data)
        seed = self.wallet_data.get("seed_phrase", "")
        if not seed:
            QMessageBox.warning(self, "Seed Unavailable", "Master seed phrase is not available in this vault.")
            return
        existing_indices = {a.get("index", 0) for a in self.wallet_data.get("accounts", [])}
        node = self.wallet_data.get("node_url", DEFAULT_NODE)
        discovered = discover_hd_accounts(seed, "", node, gap_limit=25)
        added = 0
        for d in discovered:
            if d.get("index") not in existing_indices:
                self.wallet_data["accounts"].append(d)
                existing_indices.add(d.get("index"))
                added += 1
        if added > 0:
            self.persist_wallet_accounts()
            self.refresh_addresses_ui()
            self.poll_network_data()
            QMessageBox.information(self, "HD Account Recovery", f"Recovery scan complete!\nDiscovered and restored {added} account(s) on blockchain.")
        else:
            QMessageBox.information(self, "HD Account Recovery", "All active derived accounts are already synced.")

    def get_selected_table_account_index(self) -> int:
        if not hasattr(self, 'addr_table'):
            return 0
        row = self.addr_table.currentRow()
        return row if row >= 0 else 0

    def on_address_row_double_clicked(self, row: int, col: int):
        self.set_selected_address_active()

    def set_selected_address_active(self):
        if not self.wallet_data:
            return
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data["accounts"]
        row = self.get_selected_table_account_index()
        if 0 <= row < len(accounts):
            acc = accounts[row]
            self.wallet_data["active_index"] = acc.get("index", row)
            self.wallet_data["address"] = acc["address"]
            self.wallet_data["public_key"] = acc["public_key"]
            self.wallet_data["private_key"] = acc["private_key"]
            sync_miner_address_file(acc["address"])
            self.recv_addr_lbl.setText(acc["address"])
            if hasattr(self, 'recv_path_lbl'):
                self.recv_path_lbl.setText(acc.get("derivation", f"m/44'/999'/0'/0/{acc.get('index', row)}"))
            self.render_qr_code(acc["address"])
            self.persist_wallet_accounts()
            self.refresh_addresses_ui()

    def copy_selected_table_address(self):
        if not self.wallet_data:
            return
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data["accounts"]
        row = self.get_selected_table_account_index()
        if 0 <= row < len(accounts):
            addr = accounts[row]["address"]
            QApplication.clipboard().setText(addr)

    def edit_selected_address_label(self):
        if not self.wallet_data:
            return
        ensure_wallet_accounts(self.wallet_data)
        accounts = self.wallet_data["accounts"]
        row = self.get_selected_table_account_index()
        if 0 <= row < len(accounts):
            acc = accounts[row]
            new_lbl, ok = QInputDialog.getText(self, "Edit Label", "Address Label:", QLineEdit.EchoMode.Normal, acc.get("label", ""))
            if ok and new_lbl.strip():
                acc["label"] = new_lbl.strip()
                self.persist_wallet_accounts()
                self.refresh_addresses_ui()

    # ==================== PAGE 4: CONSOLE (RPC TERMINAL) ====================
    def init_console_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(6, 6, 6, 6)
        l.setSpacing(5)

        self.cli_out = QTextEdit()
        self.cli_out.setReadOnly(True)
        self.cli_out.setFont(QFont("JetBrains Mono", 11))
        self.cli_out.setStyleSheet("background: #060608; border: 1px solid #1e1e24; color: #d4d4dc; padding: 6px;")
        self.cli_out.append("WINEX Core RPC Console (Electrum Specification)\nType 'help' for available commands.\n------------------------------------------------------------------")
        l.addWidget(self.cli_out, 1)

        in_row = QHBoxLayout()
        in_row.setSpacing(6)
        prompt = QLabel(">>")
        prompt.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        prompt.setStyleSheet("color: #ededf0; padding: 0 4px;")
        in_row.addWidget(prompt)

        self.cli_inp = QLineEdit()
        self.cli_inp.setPlaceholderText("help, balance, address, pubkey, getinfo, peers, signmessage...")
        self.cli_inp.setFont(QFont("JetBrains Mono", 11))
        self.cli_inp.returnPressed.connect(self.execute_cli_command)
        in_row.addWidget(self.cli_inp, 1)
        l.addLayout(in_row)

        return page

    def execute_cli_command(self):
        cmd = self.cli_inp.text().strip()
        self.cli_inp.clear()
        if not cmd:
            return

        self.cli_out.append(f">> {cmd}")
        parts = cmd.split()
        op = parts[0].lower()

        if op == "clear":
            self.cli_out.clear()
            return
        elif op == "help":
            out = (
                "RPC Commands:\n"
                "  help                                  List available RPC commands\n"
                "  balance                               Show confirmed portfolio balance\n"
                "  address                               Show active receiving address\n"
                "  addresses                             List all derived HD addresses\n"
                "  pubkey                                Show SECP256k1 public key hex\n"
                "  getinfo                               Query consensus state and height\n"
                "  peers                                 List connected P2P mesh peers\n"
                "  signmessage <text>                    Sign text with SECP256k1\n"
                "  clear                                 Clear console output"
            )
        elif op == "balance":
            bal = self.wallet_data.get("balance", 0.0) if self.wallet_data else 0.0
            out = f"{bal:,.4f} WNX"
        elif op == "address":
            out = self.wallet_data.get("address", "Locked") if self.wallet_data else "Locked"
        elif op == "addresses":
            if not self.wallet_data:
                out = "Locked"
            else:
                ensure_wallet_accounts(self.wallet_data)
                lines = [f"#{a.get('index',0)} {a.get('address','')} ({a.get('balance',0.0):,.4f} WNX)" for a in self.wallet_data.get("accounts", [])]
                out = "\n".join(lines)
        elif op == "pubkey":
            out = self.wallet_data.get("public_key", "Locked") if self.wallet_data else "Locked"
        elif op == "getinfo":
            try:
                st = self.api_request("GET", "api/state").json()
                out = json.dumps(st, indent=2)
            except Exception as e:
                out = f"Error: {e}"
        elif op == "peers":
            try:
                p_res = self.api_request("GET", "api/p2p/peers").json()
                out = json.dumps(p_res, indent=2)
            except Exception as e:
                out = f"Error: {e}"
        elif op == "signmessage":
            if len(parts) < 2:
                out = "Usage: signmessage <message>"
            else:
                msg = " ".join(parts[1:])
                priv = self.wallet_data.get("private_key", "") if self.wallet_data else ""
                out = sign_transaction(priv, msg) if priv else "Error: Keystore locked."
        else:
            out = f"Unknown command: '{op}'. Type 'help'."

        self.cli_out.append(out + "\n")
        self.cli_out.verticalScrollBar().setValue(self.cli_out.verticalScrollBar().maximum())

    def open_sign_verify_dialog(self):
        dlg = SignVerifyDialog(self.wallet_data, self)
        dlg.exec()

    def show_wallet_info_dialog(self):
        if not self.wallet_data:
            QMessageBox.information(self, "Keystore Info", "Keystore is locked.")
            return
        addr = self.wallet_data.get("address", "")
        pub = self.wallet_data.get("public_key", "")
        bal = self.wallet_data.get("balance", 0.0)
        acc_cnt = len(self.wallet_data.get("accounts", [1]))
        lines = [
            "Active Address : " + str(addr),
            "Derived Keys   : " + str(acc_cnt) + " HD Account(s)",
            "Public Key     : " + str(pub),
            "Total Balance  : " + f"{bal:,.4f} WNX",
            "Curve / Cipher : SECP256k1 / AES-256-GCM",
            "Gateway Peer   : " + str(self.active_node)
        ]
        QMessageBox.information(self, "Keystore Details", "\n".join(lines))

    def copy_pubkey(self):
        if self.wallet_data and "public_key" in self.wallet_data:
            QApplication.clipboard().setText(self.wallet_data["public_key"])

    # ==================== PAGE 5: NETWORK TELEMETRY ====================
    def init_network_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(6)

        card = QFrame()
        card.setProperty("class", "card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        self.net_node_lbl = self.add_stat_row("Local Sovereign Node RPC", "http://127.0.0.1:8081 (Always-On P2P Daemon)", cl)
        self.net_local_lbl = self.add_stat_row("Network Continuity Mode", "Immortal P2P Mesh (1+ Active Wallet / Miner)", cl)
        self.net_height_lbl = self.add_stat_row("Synchronized Block Height", "#0", cl)
        self.net_reward_lbl = self.add_stat_row("Current Block Subsidy", "40.0000 WNX", cl)
        self.net_pool_lbl = self.add_stat_row("Unmined PoW Pool Remaining", "10,000,000.00 WNX", cl)
        self.net_peers_lbl = self.add_stat_row("Connected Mesh Peers", "1 Active Node", cl)
        self.net_tls_lbl = self.add_stat_row("Consensus & Signature", "Double SHA-256 / SECP256k1", cl)

        l.addWidget(card)
        l.addStretch()
        return page

    def add_stat_row(self, title: str, default_val: str, layout: QVBoxLayout) -> QLabel:
        row = QHBoxLayout()
        t = QLabel(title)
        t.setStyleSheet("color: #8e8e96; font-weight: 600;")
        v = QLabel(default_val)
        v.setStyleSheet("color: #ededf0; font-family: 'JetBrains Mono'; font-weight: 600;")
        row.addWidget(t)
        row.addStretch()
        row.addWidget(v)
        layout.addLayout(row)
        return v

    # ==================== PAGE 6: PREFERENCES ====================
    def init_settings_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(6)

        card = QFrame()
        card.setProperty("class", "card")
        grid = QGridLayout(card)
        grid.setContentsMargins(12, 10, 12, 10)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(7)

        t_lbl = QLabel("Surface Polarity")
        t_lbl.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("Carbon Obsidian (Dark)", "dark")
        self.theme_combo.addItem("High-Contrast Paper (Light)", "light")
        self.theme_combo.setCurrentIndex(0 if self.config.get("theme") == "dark" else 1)
        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)
        grid.addWidget(t_lbl, 0, 0)
        grid.addWidget(self.theme_combo, 0, 1)

        l_lbl = QLabel("Session Auto-Lock")
        l_lbl.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.lock_combo = QComboBox()
        self.lock_combo.addItem("5 minutes", 5)
        self.lock_combo.addItem("15 minutes", 15)
        self.lock_combo.addItem("30 minutes", 30)
        self.lock_combo.addItem("Disabled", 0)
        self.lock_combo.setCurrentIndex(1)
        self.lock_combo.currentIndexChanged.connect(self.on_lock_timeout_changed)
        grid.addWidget(l_lbl, 1, 0)
        grid.addWidget(self.lock_combo, 1, 1)

        n_lbl = QLabel("Local P2P Node RPC")
        n_lbl.setStyleSheet("color: #8e8e96; font-weight: 600;")
        self.node_setting_inp = QLineEdit(self.config.get("node_url", DEFAULT_NODE))
        self.node_setting_inp.setFont(QFont("JetBrains Mono", 11))
        self.node_setting_inp.editingFinished.connect(self.on_node_setting_changed)
        grid.addWidget(n_lbl, 2, 0)
        grid.addWidget(self.node_setting_inp, 2, 1)

        b_seed = QPushButton("Export 12-Word Master Seed...")
        b_seed.setProperty("class", "btn-secondary")
        b_seed.clicked.connect(self.reveal_seed_phrase)
        grid.addWidget(b_seed, 3, 1)

        l.addWidget(card)
        l.addStretch()
        return page

    def on_theme_changed(self):
        theme = self.theme_combo.currentData()
        self.config["theme"] = theme
        self.save_config()
        self.apply_theme(theme)

    def on_lock_timeout_changed(self):
        mins = self.lock_combo.currentData()
        self.config["auto_lock_minutes"] = mins
        self.save_config()
        self.reset_inactivity_timer()

    def on_node_setting_changed(self):
        u = self.node_setting_inp.text().strip().rstrip("/")
        if u:
            self.config["node_url"] = u
            self.save_config()
            self.poll_network_data()

    def reveal_seed_phrase(self):
        pwd, ok = QInputDialog.getText(self, "Master Seed Export", "Enter keystore password:", QLineEdit.EchoMode.Password)
        if not ok or not pwd:
            return
        try:
            enc = load_encrypted_wallet_dict()
            dec = decrypt_wallet_data(enc, pwd)
            seed = dec.get("seed_phrase", "")
            del dec
            QMessageBox.information(self, "Master Recovery Seed", f"BIP-39 12-Word Seed:\n\n{seed}")
        except Exception:
            QMessageBox.critical(self, "Authorization Failed", "Incorrect password.")

    # ==================== PAGE 7: SPECIFICATION ====================
    def init_about_page(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(6)

        card = QFrame()
        card.setProperty("class", "card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        self.add_stat_row("Client Implementation", "WINEX Core Keystore v4.2 (Electrum Specification)", cl)
        self.add_stat_row("Consensus Algorithm", "Deterministic Double SHA-256 Proof-of-Work", cl)
        self.add_stat_row("Finite Mineable Supply", "10,000,000.0000 WNX", cl)
        self.add_stat_row("Initial Block Subsidy", "40.0000 WNX (Halving every 125,000 blocks)", cl)
        self.add_stat_row("Elliptic Curve / HD", "SECP256k1 / BIP-39 Deterministic Multi-Address", cl)
        self.add_stat_row("Keystore Encryption", "AES-256-GCM + Scrypt / PBKDF2-HMAC-SHA256", cl)
        self.add_stat_row("Network Fee Policy", "0.0000 WNX (Protocol Zero-Fee Settlement)", cl)

        l.addWidget(card)
        l.addStretch()
        return page

    # ==================== PAGE 8: ARCHITECTURAL KEYSTORE UNLOCK ====================
    def init_locked_page(self):
        self.locked_page = QWidget()
        page_layout = QVBoxLayout(self.locked_page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setFixedWidth(410)
        card.setStyleSheet("""
            QFrame {
                background: #0a0a0d;
                border: 1px solid #1e1e24;
                border-radius: 2px;
            }
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(8)

        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        if os.path.exists(LOGO_PATH):
            logo_pix = QPixmap(LOGO_PATH).scaled(26, 26, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_lbl = QLabel()
            logo_lbl.setPixmap(logo_pix)
            logo_lbl.setStyleSheet("border: none;")
            hdr.addWidget(logo_lbl)

        t = QLabel("WINEX Core Keystore")
        t.setFont(QFont("Sora", 12, QFont.Weight.Bold))
        t.setStyleSheet("color: #ededf0; border: none;")
        hdr.addWidget(t)
        hdr.addStretch()

        cipher_tag = QLabel("AES-256-GCM")
        cipher_tag.setFont(QFont("JetBrains Mono", 9.5))
        cipher_tag.setStyleSheet("color: #8e8e96; border: none;")
        hdr.addWidget(cipher_tag)
        cl.addLayout(hdr)

        path_lbl = QLabel(f"Keystore: {WALLET_FILE}")
        path_lbl.setFont(QFont("JetBrains Mono", 10))
        path_lbl.setStyleSheet("color: #8e8e96; border: none;")
        cl.addWidget(path_lbl)

        pw_lbl = QLabel("Password")
        pw_lbl.setStyleSheet("color: #d4d4dc; font-weight: 600; border: none; margin-top: 2px;")
        cl.addWidget(pw_lbl)

        self.unlock_inp = QLineEdit()
        self.unlock_inp.setEchoMode(QLineEdit.EchoMode.Password)
        self.unlock_inp.setPlaceholderText("Enter keystore password...")
        self.unlock_inp.returnPressed.connect(self.attempt_unlock)
        cl.addWidget(self.unlock_inp)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_create_new = QPushButton("New Wallet...")
        self.btn_create_new.setProperty("class", "btn-secondary")
        self.btn_create_new.clicked.connect(self.create_new_unlock_screen)

        self.btn_restore = QPushButton("Restore Seed...")
        self.btn_restore.setProperty("class", "btn-secondary")
        self.btn_restore.clicked.connect(self.restore_from_seed_unlock_screen)

        self.btn_unlock = QPushButton("Unlock Keystore")
        self.btn_unlock.setProperty("class", "btn-primary")
        self.btn_unlock.clicked.connect(self.attempt_unlock)

        btn_row.addWidget(self.btn_create_new)
        btn_row.addWidget(self.btn_restore)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_unlock)
        cl.addLayout(btn_row)

        page_layout.addWidget(card)
        return self.locked_page

    def create_new_unlock_screen(self):
        reply = QMessageBox.question(
            self,
            "Create New Keystore",
            "Do you want to create a brand new wallet?\n\nWARNING: Starting fresh will reset the local keystore on this computer. Ensure any existing 12-word seed phrase is safely backed up.\n\nProceed to create a new wallet?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            wiz = OnboardingWizardDialog(self)
            if wiz.exec() == QDialog.DialogCode.Accepted:
                w_data = wiz.result_wallet_data
                pwd = wiz.result_password
                enc = encrypt_wallet_data(w_data, pwd)
                save_wallet_file_atomic(WALLET_FILE, enc)

                self.wallet_data = w_data
                self.unlocked_password = pwd
                self.failed_unlock_attempts = 0
                self.is_locked = False
                if hasattr(self, 'tab_widget'):
                    self.init_main_tabs()
                self.stack.setCurrentWidget(self.main_container)
                self.update_mining_wallet_address_file(w_data.get('address', ''))
                self.trigger_refresh()

    def restore_from_seed_unlock_screen(self):
        reply = QMessageBox.question(
            self,
            "Restore Wallet",
            "Do you want to restore your wallet using your 12-word recovery seed phrase?\n\nThis will allow you to set a new password.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            wiz = OnboardingWizardDialog(self)
            wiz.go_to_import_seed()
            if wiz.exec() == QDialog.DialogCode.Accepted:
                w_data = wiz.result_wallet_data
                pwd = wiz.result_password
                enc = encrypt_wallet_data(w_data, pwd)
                save_wallet_file_atomic(WALLET_FILE, enc)

                self.wallet_data = w_data
                self.unlocked_password = pwd
                self.failed_unlock_attempts = 0
                self.is_locked = False
                if hasattr(self, 'tab_widget'):
                    self.tab_widget.setEnabled(True)
                if hasattr(self, 'central_stack') and hasattr(self, 'tab_widget'):
                    self.central_stack.setCurrentWidget(self.tab_widget)
                self.on_wallet_ready()
                self.switch_page(0)
                self.reset_inactivity_timer()
                QMessageBox.information(self, "Wallet Restored", "Wallet successfully restored and unlocked with your new password.")

    def lock_wallet(self):
        self.is_locked = True
        self.wallet_data = None
        self.unlocked_password = None
        if hasattr(self, 'unlock_inp'):
            self.unlock_inp.clear()
        if hasattr(self, 'tab_widget'):
            self.tab_widget.setEnabled(False)
        if hasattr(self, 'central_stack') and hasattr(self, 'locked_page'):
            self.central_stack.setCurrentWidget(self.locked_page)
            self.unlock_inp.setFocus()
        import gc
        gc.collect()

    def attempt_unlock(self):
        pwd = self.unlock_inp.text()
        if not pwd:
            return

        if hasattr(self, 'failed_unlock_attempts') and self.failed_unlock_attempts >= 5:
            QMessageBox.warning(self, "Rate Limiting", "Too many failed attempts. Please wait 10 seconds before retrying.")
            return

        try:
            enc = load_encrypted_wallet_dict()
            dec = decrypt_wallet_data(enc, pwd)
        except Exception:
            if not hasattr(self, 'failed_unlock_attempts'):
                self.failed_unlock_attempts = 0
            self.failed_unlock_attempts += 1
            remaining = max(0, 5 - self.failed_unlock_attempts)
            if remaining > 0:
                QMessageBox.critical(self, "Unlock Failed", f"Incorrect password. ({remaining} attempt(s) remaining before security delay).")
            else:
                QMessageBox.critical(self, "Unlock Failed", "Incorrect password. Security delay activated.")
            return

        # Decryption successful
        self.wallet_data = dec
        self.unlocked_password = pwd
        self.failed_unlock_attempts = 0
        self.is_locked = False
        if hasattr(self, 'tab_widget'):
            self.tab_widget.setEnabled(True)
        if hasattr(self, 'central_stack') and hasattr(self, 'tab_widget'):
            self.central_stack.setCurrentWidget(self.tab_widget)
        self.on_wallet_ready()
        self.switch_page(0)
        self.reset_inactivity_timer()
        QTimer.singleShot(100, self.poll_network_data)

    # ==================== STATE INITIALIZATION & POLLING ====================
    def check_wallet_state(self):
        if not has_any_wallet_file():
            # Trigger Onboarding Wizard
            wiz = OnboardingWizardDialog(self)
            if wiz.exec() == QDialog.DialogCode.Accepted:
                w_data = wiz.result_wallet_data
                pwd = wiz.result_password
                enc = encrypt_wallet_data(w_data, pwd)
                save_wallet_file_atomic(WALLET_FILE, enc)

                self.wallet_data = w_data
                self.unlocked_password = pwd
                self.failed_unlock_attempts = 0
                self.is_locked = False
                if hasattr(self, 'tab_widget'):
                    self.tab_widget.setEnabled(True)
                if hasattr(self, 'central_stack') and hasattr(self, 'tab_widget'):
                    self.central_stack.setCurrentWidget(self.tab_widget)
                self.on_wallet_ready()
                self.reset_inactivity_timer()
                QTimer.singleShot(100, self.poll_network_data)
            else:
                sys.exit(0)
        else:
            # Existing wallet - prompt for unlock
            self.lock_wallet()

    def on_wallet_ready(self):
        if self.wallet_data:
            ensure_wallet_accounts(self.wallet_data)
            addr = self.wallet_data.get("address", "")
            sync_miner_address_file(addr)
            self.recv_addr_lbl.setText(addr)
            self.render_qr_code(addr)
            self.refresh_addresses_ui()
            self.switch_page(0)
            self.poll_network_data()

    def poll_network_data(self):
        threading.Thread(target=ensure_background_node, daemon=True).start()
        if not self.wallet_data or self.is_locked:
            return
        if hasattr(self, 'poller_thread') and self.poller_thread and self.poller_thread.isRunning():
            return
        ensure_wallet_accounts(self.wallet_data)
        addr = self.wallet_data.get("address", "")
        addr_list = [a.get("address", "") for a in self.wallet_data.get("accounts", []) if a.get("address")]
        nodes = self.get_candidate_nodes()
        self.poller_thread = NetworkPollerWorker(nodes, addr, addr_list, self)
        self.poller_thread.data_received.connect(self.on_network_data_received)
        self.poller_thread.start()

    def on_network_data_received(self, data: dict):
        if not self.wallet_data or self.is_locked:
            return

        # 1. Update Multi-Address Balances & Total Portfolio Balance
        if "balances_map" in data:
            bmap = data["balances_map"]
            ensure_wallet_accounts(self.wallet_data)
            total_bal = 0.0
            for acc in self.wallet_data.get("accounts", []):
                a = acc.get("address", "")
                if a in bmap:
                    bal_val = float(bmap[a])
                    acc["balance"] = bal_val
                    total_bal += bal_val
            self.wallet_data["balance"] = total_bal
            if not self.balance_hidden and hasattr(self, 'bal_display'):
                self.bal_display.setText(f"Balance: {total_bal:,.4f} WNX")
            self.refresh_addresses_ui()
        elif "balance" in data:
            bal = data["balance"]
            self.wallet_data["balance"] = bal
            if not self.balance_hidden and hasattr(self, 'bal_display'):
                self.bal_display.setText(f"Balance: {bal:,.4f} WNX")
            self.refresh_addresses_ui()

        # 2. Update Status
        if "status" in data:
            st = data["status"]
            height = st.get("block_height", 0)
            if hasattr(self, 'net_height_lbl'):
                self.net_height_lbl.setText(f"#{height}")
            if hasattr(self, 'sb_height_lbl'):
                self.sb_height_lbl.setText(f"Height: {height}")
            if hasattr(self, 'net_reward_lbl'):
                self.net_reward_lbl.setText(f"{st.get('block_reward', 40.0):.4f} WNX")
            if hasattr(self, 'net_pool_lbl'):
                self.net_pool_lbl.setText(f"{st.get('pool_remaining', st.get('mining_pool_available', 10000000.0)):,.2f} WNX")
            if hasattr(self, 'net_peers_lbl'):
                self.net_peers_lbl.setText(f"{st.get('peer_count', 1)} Active Nodes")

        # Telemetry node mode indicator
        if data.get("is_local_core"):
            if hasattr(self, 'sb_node_lbl'):
                self.sb_node_lbl.setText("Node: Local P2P Core (:8081)")
                self.sb_node_lbl.setStyleSheet("color: #22c55e; font-weight: 700; padding: 0 8px;")
                self.sb_node_lbl.setToolTip("Autonomous Mode: Running directly against local ledger")
        else:
            if hasattr(self, 'sb_node_lbl'):
                self.sb_node_lbl.setText("Node: P2P Mesh (:8081)")
                self.sb_node_lbl.setStyleSheet("color: #22c55e; font-weight: 700; padding: 0 8px;")

        # 3. Update Peers
        if "peers" in data:
            self.discovered_peers = data["peers"]

        # 4. Update Blocks / Tx History (Informational mining & transfer ledger)
        if "blocks" in data and hasattr(self, 'recent_table'):
            raw_blocks = data["blocks"]
            if isinstance(raw_blocks, list):
                # Never show Block #0 (Network Reserve) on the public History ledger
                filtered_blocks = [
                    b for b in raw_blocks
                    if isinstance(b, dict) and b.get("block_index", b.get("index", 0)) != 0
                ]

                # Strictly sort by timestamp descending (newest on top)
                def get_sort_key(b):
                    try:
                        ts = float(b.get("timestamp") or 0.0)
                    except (ValueError, TypeError):
                        ts = 0.0
                    try:
                        idx = int(b.get("block_index", b.get("index", 0)) or 0)
                    except (ValueError, TypeError):
                        idx = 0
                    return (ts, idx)

                filtered_blocks.sort(key=get_sort_key, reverse=True)

                self.recent_table.setRowCount(len(filtered_blocks))
                for i, b in enumerate(filtered_blocks):
                    status_item = QTableWidgetItem("Mined")
                    status_item.setForeground(QColor("#22c55e"))
                    self.recent_table.setItem(i, 0, status_item)
                    b_idx = b.get("block_index", b.get("index", 0))
                    miner_addr = b.get("miner", "Unknown")
                    short_miner = miner_addr[:14] + "..." if len(miner_addr) > 16 else miner_addr
                    reward_val = b.get("reward", 40.0)
                    self.recent_table.setItem(i, 1, QTableWidgetItem(f"Block #{b_idx} mined by {short_miner}"))
                    self.recent_table.setItem(i, 2, QTableWidgetItem(f"+{reward_val:.4f} WNX"))
                    ts_val = b.get("timestamp", 0)
                    ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_val)) if ts_val else "-"
                    self.recent_table.setItem(i, 3, QTableWidgetItem(ts_str))

def main():
    harden_process_security()
    threading.Thread(target=ensure_background_node, daemon=True).start()
    app = QApplication(sys.argv)
    app.setApplicationName("winex-wallet")
    app.setDesktopFileName("winex-wallet")
    app.setQuitOnLastWindowClosed(True)
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        appIcon = QIcon(LOGO_PATH)
        app.setWindowIcon(appIcon)
    win = WinexWalletApp()
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        win.setWindowIcon(QIcon(LOGO_PATH))
    win.show()
    code = app.exec()
    os._exit(code)

if __name__ == "__main__":
    main()
