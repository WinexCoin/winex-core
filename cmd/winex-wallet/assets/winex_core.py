import os
import json
import time
import math
import hashlib
import sqlite3
import threading
import requests
import ecdsa
from typing import List, Dict, Optional, Tuple

DB_PATH = os.environ.get(
    "WINEX_DB_PATH",
    "/home/ubuntu/winex-node/winex_chain.db"
    if os.path.exists("/home/ubuntu/winex-node/winex_chain.db")
    else os.path.join(os.path.expanduser("~/.winex"), "winex_chain.db"),
)

# Genesis Protocol Distribution (Block #0 Network Reserve)
GENESIS_VAULT_ADDR = "WNX5B15097CB2203643C472AB992FA9FB1A"
GENESIS_VAULT_SUPPLY = 2_100_000.0

MINING_POOL_INITIAL = 10_000_000.0
MINING_DIFFICULTY = 6

# ==================== BITCOIN 2100 IMMUTABLE CONSENSUS RULES ====================
# Total unmined pool: 10,000,000 WNX.
# 1 Block = Fixed ~15 minutes (900 seconds) independent of network hashrate.
INITIAL_BLOCK_REWARD = 40.0
HALVING_INTERVAL_BLOCKS = 125_000
TARGET_BLOCK_TIME = 900.0   # Fixed 15 minutes (900 seconds) consensus target
RETARGET_WINDOW = 20        # Retarget evaluation window
MAX_REORG_DEPTH = 10        # Deep reorganization protection against 51% attacks

def get_block_reward(block_index: int) -> float:
    if block_index <= 0:
        return 0.0
    era = (block_index - 1) // HALVING_INTERVAL_BLOCKS
    if era >= 20:
        return 0.0
    return round(INITIAL_BLOCK_REWARD / (2 ** era), 6)

# Scarcity Dynamic Difficulty Algorithm (Bitcoin Difficulty Model)
# Calibrated for baseline 15-minute target block time on 100 MH/s baseline (~90-95 Billion hashes)
BASE_TARGET_INT = int("000000000c370000000000000000000000000000000000000000000000000000", 16)

def calculate_dynamic_target(pool_remaining: float) -> Tuple[str, float]:
    pool_remaining = max(0.0, min(10_000_000.0, pool_remaining))
    mined = 10_000_000.0 - pool_remaining
    progress = mined / 10_000_000.0
    multiplier = 1.0 + (progress * 3.0) + ((progress ** 3) * 15.0)
    target_int = int(BASE_TARGET_INT / multiplier)
    target_hex = hex(target_int)[2:].zfill(64)
    return target_hex, multiplier

BOOTSTRAP_SEEDS = [
    "https://winexcoin.com"
]

def generate_keypair() -> Tuple[str, str, str]:
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    priv_hex = sk.to_string().hex()
    pub_hex = vk.to_string().hex()
    addr_hash = hashlib.sha256(vk.to_string()).hexdigest()[:32]
    address = "WNX" + addr_hash.upper()
    return priv_hex, pub_hex, address

def sign_data(private_key_hex: str, message: str) -> str:
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    sig = sk.sign(message.encode('utf-8'), hashfunc=hashlib.sha256)
    return sig.hex()

def verify_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        pub_bytes = bytes.fromhex(public_key_hex.strip())
        sig_bytes = bytes.fromhex(signature_hex.strip())
        if len(pub_bytes) != 64 or len(sig_bytes) != 64:
            return False
        vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=ecdsa.SECP256k1)
        msg_bytes = message.encode('utf-8')
        try:
            if vk.verify(sig_bytes, msg_bytes, hashfunc=hashlib.sha256):
                return True
        except Exception:
            pass
        return vk.verify(sig_bytes, msg_bytes, hashfunc=hashlib.sha1)
    except Exception:
        return False

def calculate_merkle_root(tx_ids: List[str]) -> str:
    if not tx_ids:
        return hashlib.sha256(b"empty").hexdigest()
    hashes = list(tx_ids)
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_hashes.append(hashlib.sha256(combined.encode('utf-8')).hexdigest())
        hashes = new_hashes
    return hashes[0]

def compute_pow_hash(index: int, prev_hash: str, merkle: str, miner_addr: str, timestamp: float, nonce: int) -> str:
    raw = f"{index}:{prev_hash}:{merkle}:{miner_addr}:{timestamp:.4f}:{nonce}"
    first_round = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    salt = hashlib.sha256((miner_addr + raw[:16]).encode('utf-8')).hexdigest()
    second_round = hashlib.sha256((first_round + salt).encode('utf-8')).hexdigest()
    return second_round

class WinexBlockchain:
    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            with self.conn:
                self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute("PRAGMA synchronous=NORMAL;")
                self.conn.execute("PRAGMA busy_timeout=5000;")
        self._init_db()
        if self.get_height() == 0:
            self._create_genesis_block()
        self._init_peers()
        try:
            os.chmod(db_path, 0o600)
        except Exception:
            pass

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    block_index INTEGER PRIMARY KEY,
                    hash TEXT UNIQUE,
                    prev_hash TEXT,
                    merkle_root TEXT,
                    nonce INTEGER,
                    difficulty INTEGER,
                    timestamp REAL,
                    tx_count INTEGER,
                    miner TEXT,
                    raw_data TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_id TEXT PRIMARY KEY,
                    block_index INTEGER,
                    sender TEXT,
                    recipient TEXT,
                    amount REAL,
                    fee REAL,
                    timestamp REAL,
                    signature TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS balances (
                    address TEXT PRIMARY KEY,
                    balance REAL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS mempool (
                    tx_id TEXT PRIMARY KEY,
                    sender TEXT,
                    recipient TEXT,
                    amount REAL,
                    fee REAL,
                    timestamp REAL,
                    pub_key TEXT,
                    signature TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    url TEXT PRIMARY KEY,
                    last_seen REAL
                )
            """)

    def _init_peers(self):
        with self.conn:
            for s in BOOTSTRAP_SEEDS:
                self.conn.execute("INSERT OR IGNORE INTO peers (url, last_seen) VALUES (?, ?)", (s, time.time()))

    def add_peer(self, url: str, client_ip: str = "") -> bool:
        url = (url or "").strip().rstrip('/')
        if url.startswith("auto:") and client_ip and client_ip not in ("unknown", "127.0.0.1", "::1"):
            try:
                port = int(url.split(":", 1)[1])
                if 1024 <= port <= 65535:
                    url = f"http://{client_ip}:{port}"
                else:
                    return False
            except Exception:
                return False
        if not url.startswith("http://") and not url.startswith("https://"):
            return False
        try:
            import ipaddress
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            if not hostname or len(url) > 256:
                return False
            blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}
            env_ip = os.environ.get("WINEX_NODE_IP")
            if env_ip:
                blocked.add(env_ip)
            if hostname in blocked or hostname.endswith(".local") or hostname.endswith(".internal"):
                return False
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
                    ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
                    return False
            except ValueError:
                pass
        except Exception:
            return False

        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM peers")
            if cur.fetchone()[0] >= 100:
                self.conn.execute("DELETE FROM peers WHERE url IN (SELECT url FROM peers ORDER BY last_seen ASC LIMIT 1)")
            self.conn.execute("INSERT OR REPLACE INTO peers (url, last_seen) VALUES (?, ?)", (url, time.time()))
        return True

    def get_peers(self) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT url FROM peers ORDER BY last_seen DESC LIMIT 50")
        return [r[0] for r in cur.fetchall()]

    def broadcast_to_peers(self, endpoint: str, data: dict):
        peers = self.get_peers()
        for p in peers:
            try:
                requests.post(f"{p}{endpoint}", json=data, timeout=2)
            except Exception:
                pass

    def get_height(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM blocks")
        return cur.fetchone()[0]

    def get_balance(self, address: str) -> float:
        if not address or len(address) > 45 or not address.startswith("WNX"):
            return 0.0
        cur = self.conn.cursor()
        cur.execute("SELECT balance FROM balances WHERE address = ?", (address,))
        row = cur.fetchone()
        return float(row[0]) if row else 0.0

    def get_pool_remaining(self) -> float:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = 'mining_pool'")
        row = cur.fetchone()
        return float(row[0]) if row else MINING_POOL_INITIAL

    def _create_genesis_block(self):
        timestamp = 1792425120.0  # Fixed deterministic genesis timestamp
        prev_hash = "0" * 64

        genesis_tx = {
            "tx_id": hashlib.sha256(f"GENESIS_{GENESIS_VAULT_ADDR}_{GENESIS_VAULT_SUPPLY}_{timestamp}".encode()).hexdigest(),
            "sender": "NETWORK_INIT",
            "recipient": GENESIS_VAULT_ADDR,
            "amount": GENESIS_VAULT_SUPPLY,
            "fee": 0.0,
            "timestamp": timestamp,
            "signature": "GENESIS_NETWORK_INIT_HASH"
        }

        merkle = calculate_merkle_root([genesis_tx["tx_id"]])
        diff = 4
        target = "0" * diff
        nonce = 0

        while True:
            b_hash = compute_pow_hash(0, prev_hash, merkle, GENESIS_VAULT_ADDR, timestamp, nonce)
            if b_hash.startswith(target):
                break
            nonce += 1

        with self.conn:
            self.conn.execute(
                "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (0, b_hash, prev_hash, merkle, nonce, diff, timestamp, 1, "GENESIS_NODE", json.dumps([genesis_tx]))
            )
            self.conn.execute(
                "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (genesis_tx["tx_id"], 0, genesis_tx["sender"], genesis_tx["recipient"],
                 genesis_tx["amount"], genesis_tx["fee"], genesis_tx["timestamp"], genesis_tx["signature"])
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO balances (address, balance) VALUES (?, ?)",
                (GENESIS_VAULT_ADDR, GENESIS_VAULT_SUPPLY)
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('mining_pool', ?)",
                (str(MINING_POOL_INITIAL),)
            )

    def calculate_current_target(self, pool_remaining: float) -> Tuple[str, float]:
        base_target_hex, base_mult = calculate_dynamic_target(pool_remaining)
        base_int = int(base_target_hex, 16)

        cur = self.conn.cursor()
        cur.execute("SELECT block_index, timestamp FROM blocks ORDER BY block_index DESC LIMIT 8")
        rows = cur.fetchall()
        if not rows:
            return base_target_hex, base_mult

        now = time.time()
        last_ts = rows[0]["timestamp"]
        elapsed_since_last = max(0.0, now - last_ts)

        active_deltas = []
        for i in range(len(rows) - 1):
            d = rows[i]["timestamp"] - rows[i + 1]["timestamp"]
            if d > 0:
                active_deltas.append(d)

        # Include real-time elapsed duration if it exceeds the 15-minute target
        if elapsed_since_last > TARGET_BLOCK_TIME:
            active_deltas.append(elapsed_since_last)

        if not active_deltas:
            avg_interval = TARGET_BLOCK_TIME
        else:
            avg_interval = sum(active_deltas) / len(active_deltas)

        ratio = max(0.01, min(100.0, avg_interval / TARGET_BLOCK_TIME))

        # Real-time Emergency Difficulty Adjustment (EDA):
        # If active hashrate dropped (e.g. GPU disconnected and only CPU is mining),
        # dynamically ease the target so the block is found in equilibrium.
        if elapsed_since_last > TARGET_BLOCK_TIME:
            extra_periods = (elapsed_since_last - TARGET_BLOCK_TIME) / TARGET_BLOCK_TIME
            eda_factor = min(100.0, 1.0 + (extra_periods * 3.0))
            ratio = min(100.0, ratio * eda_factor)

        # Cap minimum difficulty at 00000ffff...
        max_target_cap = int("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        adjusted_int = min(max_target_cap, max(1, int(base_int * ratio)))
        target_hex = hex(adjusted_int)[2:].zfill(64)
        return target_hex, round(base_mult / max(0.001, ratio), 2)

    def get_mining_template(self) -> Dict:
        cur = self.conn.cursor()
        cur.execute("SELECT hash, block_index FROM blocks ORDER BY block_index DESC LIMIT 1")
        last = cur.fetchone()
        prev_hash = last["hash"]
        new_index = last["block_index"] + 1

        cur.execute("SELECT * FROM mempool ORDER BY fee DESC LIMIT 50")
        rows = cur.fetchall()
        tx_ids = [r["tx_id"] for r in rows]
        parts = [f"block_{new_index}_merkle"] + tx_ids
        merkle = hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()

        pool_remaining = self.get_pool_remaining()
        target_hex, multiplier = self.calculate_current_target(pool_remaining)
        block_reward = get_block_reward(new_index)
        actual_reward = min(block_reward, pool_remaining)

        return {
            "block_index": new_index,
            "prev_hash": prev_hash,
            "merkle_root": merkle,
            "difficulty": MINING_DIFFICULTY,
            "target": target_hex,
            "target_prefix": target_hex[:7],
            "difficulty_multiplier": multiplier,
            "reward": round(actual_reward, 6),
            "pool_remaining": pool_remaining,
            "tx_count": len(rows),
            "server_time": time.time()
        }

    def verify_and_submit_block(self, miner_address: str, block_index: int, nonce: int,
                                timestamp: float, reported_hash: str) -> Tuple[bool, str]:
        if not miner_address.startswith("WNX") or len(miner_address) < 20:
            return False, "Invalid miner wallet address."

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT hash, block_index, timestamp FROM blocks ORDER BY block_index DESC LIMIT 1")
            last = cur.fetchone()

            if block_index != last["block_index"] + 1:
                return False, "Stale or invalid block height."

            # Timestamp validation against time-warp attack (allows up to 24h drift for VM/timezone tolerances)
            now = time.time()
            if timestamp < last["timestamp"] - 60:
                return False, "Block timestamp cannot precede previous block."
            if timestamp > now + 86400:
                return False, "Block timestamp cannot exceed 24 hours in future."

            prev_hash = last["hash"]

            cur.execute("SELECT * FROM mempool ORDER BY fee DESC, timestamp ASC LIMIT 50")
            rows = cur.fetchall()

            pool_remaining = self.get_pool_remaining()
            block_reward = get_block_reward(block_index)
            actual_reward = min(block_reward, pool_remaining)

            txs = []
            total_fees = 0.0
            for r in rows:
                tx = {
                    "tx_id": r["tx_id"],
                    "sender": r["sender"],
                    "recipient": r["recipient"],
                    "amount": float(r["amount"]),
                    "fee": float(r["fee"]),
                    "timestamp": float(r["timestamp"]),
                    "signature": r["signature"]
                }
                txs.append(tx)
                total_fees += float(r["fee"])

            parts = [f"block_{block_index}_merkle"] + [t["tx_id"] for t in txs]
            merkle = hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()
            coinbase_tx = {
                "tx_id": hashlib.sha256(f"COINBASE_{miner_address}_{block_index}_{timestamp}".encode()).hexdigest(),
                "sender": "COINBASE",
                "recipient": miner_address,
                "amount": round(actual_reward + total_fees, 6),
                "fee": 0.0,
                "timestamp": timestamp,
                "signature": "MINER_PROOF_OF_WORK"
            }

            # Verify mathematical PoW & Scarcity Target
            calculated_hash = compute_pow_hash(block_index, prev_hash, merkle, miner_address, timestamp, nonce)
            target_hex, _ = self.calculate_current_target(pool_remaining)

            is_valid_pow = (
                calculated_hash == reported_hash and
                calculated_hash <= target_hex
            )
            if not is_valid_pow:
                return False, "Invalid Proof-of-Work: Hash does not meet difficulty target."

            with self.conn:
                valid_txs = []
                valid_fees = 0.0
                for t in txs:
                    s_bal = self.get_balance(t["sender"])
                    cost = round(float(t["amount"]) + float(t["fee"]), 6)
                    if s_bal < cost:
                        self.conn.execute("DELETE FROM mempool WHERE tx_id = ?", (t["tx_id"],))
                        continue
                    r_bal = self.get_balance(t["recipient"])
                    self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?, ?)", (t["sender"], round(s_bal - cost, 6)))
                    r_bal = self.get_balance(t["recipient"])
                    self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?, ?)", (t["recipient"], round(r_bal + float(t["amount"]), 6)))
                    self.conn.execute("DELETE FROM mempool WHERE tx_id = ?", (t["tx_id"],))
                    valid_txs.append(t)
                    valid_fees += float(t["fee"])

                coinbase_tx["amount"] = round(actual_reward + valid_fees, 6)
                committed_txs = [coinbase_tx] + valid_txs

                self.conn.execute(
                    "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (block_index, calculated_hash, prev_hash, merkle, nonce, MINING_DIFFICULTY,
                     timestamp, len(committed_txs), miner_address, json.dumps(committed_txs))
                )
                for t in committed_txs:
                    self.conn.execute(
                        "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (t["tx_id"], block_index, t["sender"], t["recipient"], t["amount"], t["fee"], t["timestamp"], t["signature"])
                    )
                miner_bal = self.get_balance(miner_address)
                self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?, ?)", (miner_address, round(miner_bal + actual_reward + valid_fees, 6)))

                new_pool = round(max(0.0, pool_remaining - actual_reward), 6)
                self.conn.execute("UPDATE meta SET value = ? WHERE key = 'mining_pool'", (str(new_pool),))

        # P2P Gossip Broadcast to all known peer nodes
        try:
            self.broadcast_to_peers("/p2p/receive_block", {
                "block_index": block_index,
                "miner_address": miner_address,
                "nonce": nonce,
                "timestamp": timestamp,
                "hash": calculated_hash
            })
        except Exception:
            pass

        return True, calculated_hash

    def add_transaction_to_mempool(self, sender: str, recipient: str, amount: float, fee: float,
                                   pub_key: str, signature: str, timestamp: Optional[float] = None) -> Tuple[bool, str]:
        # Input validation & Dust Protection
        try:
            amount = round(float(amount), 8)
            fee = round(float(fee), 8)
        except Exception:
            return False, "Invalid numeric format."

        if math.isnan(amount) or math.isinf(amount) or amount < 0.00000001:
            return False, "Invalid transfer amount (Minimum transfer is 0.00000001 WNX)."
        if math.isnan(fee) or math.isinf(fee) or fee < 0 or fee > 1000.0:
            return False, "Invalid fee amount (Must be between 0 and 1000 WNX)."
        if not recipient.startswith("WNX") or len(recipient) < 20 or len(recipient) > 42:
            return False, "Invalid recipient WNX address."
        if sender == recipient:
            return False, "Cannot send transaction to self."

        # Anti-replay timestamp verification (with VM/skew tolerance)
        now = time.time()
        tx_ts = timestamp if timestamp is not None else now
        if timestamp is not None:
            if timestamp < now - 86400:
                return False, "Transaction timestamp is too old (Replay protection)."
            if timestamp > now + 86400:
                return False, "Transaction timestamp cannot be in the future."

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM mempool")
            if cur.fetchone()[0] >= 5000:
                return False, "Mempool at maximum capacity (5000 TX). Please wait for next block."

            # Check for duplicate signature or duplicate tx in mempool or recent transactions
            cur.execute("SELECT 1 FROM mempool WHERE signature = ? LIMIT 1", (signature,))
            if cur.fetchone():
                return False, "Transaction is already pending in mempool."
            cur.execute("SELECT 1 FROM transactions WHERE signature = ? LIMIT 1", (signature,))
            if cur.fetchone():
                return False, "Transaction already confirmed (Replay protection)."

            sender_balance = self.get_balance(sender)
            cur.execute("SELECT SUM(amount + fee) FROM mempool WHERE sender = ?", (sender,))
            pending_outgoing = cur.fetchone()[0] or 0.0
            if sender_balance < (amount + fee + pending_outgoing):
                return False, f"Insufficient balance. Available: {sender_balance} WNX, Pending: {pending_outgoing} WNX"

            try:
                pub_bytes = bytes.fromhex(pub_key.strip())
                if len(pub_bytes) != 64:
                    return False, "Invalid public key length (Expected 64-byte hex)."
            except Exception:
                return False, "Invalid public key hex format."

            expected_addr = "WNX" + hashlib.sha256(pub_bytes).hexdigest()[:32].upper()
            if expected_addr != sender:
                return False, "Public key does not match sender address."

            # Verify cryptographic signature (checking all canonical formats)
            valid_sig = False
            candidate_messages = []
            if timestamp is not None:
                candidate_messages.append(f"{sender}:{recipient}:{amount:.8f}:{fee:.8f}:{timestamp:.4f}")
                candidate_messages.append(f"{sender}:{recipient}:{amount:.4f}:{fee:.4f}:{timestamp:.4f}")
                candidate_messages.append(f"{sender}:{recipient}:{amount}:{fee}:{timestamp}")
            candidate_messages.append(f"{sender}:{recipient}:{amount:.8f}:{fee:.8f}")
            candidate_messages.append(f"{sender}:{recipient}:{amount}:{fee}")
            candidate_messages.append(f"{sender}:{recipient}:{amount:.4f}:{fee:.4f}")

            for m in candidate_messages:
                if verify_signature(pub_key, m, signature):
                    valid_sig = True
                    break

            if not valid_sig:
                return False, "Invalid cryptographic transaction signature."

            tx_id = hashlib.sha256(f"{sender}:{recipient}:{amount}:{fee}:{tx_ts}:{signature}".encode()).hexdigest()

            cur.execute("SELECT 1 FROM mempool WHERE tx_id = ? LIMIT 1", (tx_id,))
            if cur.fetchone():
                return False, "Transaction already exists in mempool."
            cur.execute("SELECT 1 FROM transactions WHERE tx_id = ? LIMIT 1", (tx_id,))
            if cur.fetchone():
                return False, "Transaction already confirmed (Replay protection)."

            with self.conn:
                self.conn.execute(
                    "INSERT INTO mempool VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (tx_id, sender, recipient, amount, fee, tx_ts, pub_key, signature)
                )

        # Broadcast tx to peers
        try:
            self.broadcast_to_peers("/p2p/receive_tx", {
                "sender": sender, "recipient": recipient,
                "amount": amount, "fee": fee, "pub_key": pub_key, "signature": signature,
                "timestamp": tx_ts
            })
        except Exception:
            pass

        return True, tx_id

    def get_latest_blocks(self, limit: int = 15) -> List[Dict]:
        limit = max(1, min(100, int(limit)))
        cur = self.conn.cursor()
        cur.execute("SELECT block_index, hash, prev_hash, nonce, difficulty, timestamp, tx_count, miner FROM blocks ORDER BY block_index DESC LIMIT ?", (limit,))
        res = []
        for r in cur.fetchall():
            d = dict(r)
            d["reward"] = get_block_reward(d["block_index"])
            res.append(d)
        return res

    def get_latest_transactions(self, limit: int = 20) -> List[Dict]:
        limit = max(1, min(100, int(limit)))
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def get_block_by_id(self, block_id: str) -> Optional[Dict]:
        cur = self.conn.cursor()
        height = self.get_height()
        if str(block_id).isdigit():
            cur.execute("SELECT * FROM blocks WHERE block_index = ?", (int(block_id),))
        else:
            cur.execute("SELECT * FROM blocks WHERE hash = ?", (str(block_id).strip(),))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["reward"] = get_block_reward(d["block_index"])
        d["confirmations"] = max(1, height - d["block_index"] + 1)
        try:
            d["transactions"] = json.loads(d.get("raw_data") or "[]")
        except Exception:
            d["transactions"] = []
        d.pop("raw_data", None)
        return d

    def get_transaction_by_id(self, tx_id: str) -> Optional[Dict]:
        tx_id = (tx_id or "").strip()
        cur = self.conn.cursor()
        height = self.get_height()
        cur.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,))
        row = cur.fetchone()
        if row:
            d = dict(row)
            b_idx = d.get("block_index", 0)
            d["status"] = "confirmed"
            d["confirmations"] = max(1, height - b_idx + 1) if b_idx > 0 else 1
            cur.execute("SELECT hash FROM blocks WHERE block_index = ?", (b_idx,))
            b_row = cur.fetchone()
            d["block_hash"] = b_row["hash"] if b_row else ""
            return d
        cur.execute("SELECT * FROM mempool WHERE tx_id = ?", (tx_id,))
        m_row = cur.fetchone()
        if m_row:
            d = dict(m_row)
            d["block_index"] = None
            d["block_hash"] = None
            d["status"] = "unconfirmed"
            d["confirmations"] = 0
            return d
        return None

    def get_address_info(self, address: str, limit: int = 50) -> Dict:
        address = (address or "").strip()
        limit = max(1, min(200, int(limit)))
        height = self.get_height()
        confirmed_bal = self.get_balance(address)
        cur = self.conn.cursor()
        cur.execute("SELECT COALESCE(SUM(amount), 0.0) FROM mempool WHERE recipient = ?", (address,))
        pending_in = float(cur.fetchone()[0] or 0.0)
        cur.execute("SELECT COALESCE(SUM(amount + fee), 0.0) FROM mempool WHERE sender = ?", (address,))
        pending_out = float(cur.fetchone()[0] or 0.0)
        cur.execute(
            "SELECT * FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC LIMIT ?",
            (address, address, limit)
        )
        txs = []
        for r in cur.fetchall():
            td = dict(r)
            b_idx = td.get("block_index", 0)
            td["confirmations"] = max(1, height - b_idx + 1) if b_idx > 0 else 1
            td["status"] = "confirmed"
            txs.append(td)
        return {
            "address": address,
            "is_valid": self.validate_address(address),
            "confirmed_balance": round(confirmed_bal, 6),
            "unconfirmed_incoming": round(pending_in, 6),
            "unconfirmed_outgoing": round(pending_out, 6),
            "spendable_balance": round(max(0.0, confirmed_bal - pending_out), 6),
            "tx_count": len(txs),
            "transactions": txs
        }

    @staticmethod
    def validate_address(address: str) -> bool:
        if not isinstance(address, str) or len(address) != 35 or not address.startswith("WNX"):
            return False
        hex_part = address[3:]
        return all(c in "0123456789ABCDEF" for c in hex_part)

    def sync_blocks_from_peer(self, peer_url: str) -> int:
        synced_count = 0
        try:
            res = requests.get(f"{peer_url}/api/status", timeout=3)
            if res.status_code != 200:
                return 0
            peer_height = res.json().get("block_height", 0)
            my_height = self.get_height()
            if peer_height > my_height:
                b_res = requests.get(f"{peer_url}/p2p/blocks_export?from_index={my_height + 1}", timeout=15)
                if b_res.status_code == 200:
                    blocks = b_res.json()
                    for b in blocks:
                        with self.lock:
                            cur = self.conn.cursor()
                            cur.execute("SELECT hash, block_index, timestamp FROM blocks ORDER BY block_index DESC LIMIT 1")
                            last = cur.fetchone()
                            if b["block_index"] != last["block_index"] + 1 or b["prev_hash"] != last["hash"]:
                                break

                            blk_ts = float(b["timestamp"])
                            if blk_ts < last["timestamp"] - 60 or blk_ts > time.time() + 7200:
                                break

                            pool_remaining = self.get_pool_remaining()
                            target_hex, _ = self.calculate_current_target(pool_remaining)

                            calc_hash = compute_pow_hash(b["block_index"], b["prev_hash"], b["merkle_root"], b["miner"], blk_ts, int(b["nonce"]))
                            if calc_hash != b["hash"] or calc_hash > target_hex:
                                break

                            raw_txs = b.get("raw_data") or b.get("tx_data") or []
                            txs = json.loads(raw_txs) if isinstance(raw_txs, str) else raw_txs
                            tx_ids = [t.get("tx_id", "") for t in txs]
                            if calculate_merkle_root(tx_ids) != b["merkle_root"]:
                                break

                            reward = min(get_block_reward(b["block_index"]), pool_remaining)
                            coinbase_count = 0
                            total_fees = 0.0
                            block_valid = True
                            for t in txs:
                                amt = float(t.get("amount", 0.0))
                                fee = float(t.get("fee", 0.0))
                                if math.isnan(amt) or math.isinf(amt) or math.isnan(fee) or math.isinf(fee) or amt < 0 or fee < 0:
                                    block_valid = False
                                    break
                                if t.get("sender") == "COINBASE":
                                    coinbase_count += 1
                                else:
                                    if amt < 0.00000001 or fee > 1000.0 or t.get("sender") == t.get("recipient"):
                                        block_valid = False
                                        break
                                    total_fees += fee

                            if not block_valid or coinbase_count > 1:
                                break

                            for t in txs:
                                if t.get("sender") == "COINBASE":
                                    if float(t.get("amount", 0.0)) > round(reward + total_fees, 6) + 1e-5:
                                        block_valid = False
                                        break
                            if not block_valid:
                                break

                            with self.conn:
                                committed_txs = []
                                for t in txs:
                                    amt = round(float(t["amount"]), 6)
                                    fee = round(float(t["fee"]), 6)
                                    if t["sender"] != "COINBASE":
                                        s_bal = self.get_balance(t["sender"])
                                        cost = round(amt + fee, 6)
                                        if s_bal < cost:
                                            self.conn.execute("DELETE FROM mempool WHERE tx_id = ?", (t["tx_id"],))
                                            continue
                                        self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?, ?)", (t["sender"], round(s_bal - cost, 6)))
                                    r_bal = self.get_balance(t["recipient"])
                                    self.conn.execute("INSERT OR REPLACE INTO balances VALUES (?, ?)", (t["recipient"], round(r_bal + amt, 6)))
                                    self.conn.execute("DELETE FROM mempool WHERE tx_id = ?", (t["tx_id"],))
                                    self.conn.execute(
                                        "INSERT OR REPLACE INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                        (t["tx_id"], b["block_index"], t["sender"], t["recipient"],
                                         amt, fee, float(t["timestamp"]), t["signature"])
                                    )
                                    committed_txs.append(t)

                                self.conn.execute(
                                    "INSERT OR REPLACE INTO blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (b["block_index"], b["hash"], b["prev_hash"], b["merkle_root"],
                                     b["nonce"], b["difficulty"], blk_ts, len(committed_txs),
                                     b["miner"], json.dumps(committed_txs))
                                )

                                new_pool = round(max(0.0, pool_remaining - reward), 6)
                                self.conn.execute("UPDATE meta SET value = ? WHERE key = 'mining_pool'", (str(new_pool),))
                                synced_count += 1
        except Exception:
            pass
        return synced_count

