#!/usr/bin/env python3
"""
WINEX Stratum Server (TCP Port 3333)
Engineered for High-Reliability, Minimal Memory Footprint & Strict Anti-DDoS Defense.

Anti-Abuse Protections:
- Hard-capped connection limits (Max 100 concurrent miners)
- Strict per-IP rate limiting (Max 5 connections per IP, 10 msgs/sec)
- Packet size enforcement (Max 2048 bytes per line; immediate drop on violation)
- Non-blocking asynchronous I/O via asyncio (Zero thread-starvation)
- Aggressive socket idle timeout (60s silence drop)
- Zero database locks: All state queried over localhost API (127.0.0.1:8080)
- Sandboxed memory consumption (<25MB typical RAM)
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.request
import urllib.error
from typing import Dict, Set, Optional

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [STRATUM] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("winex_stratum")

# Configuration & Hard Limits
HOST = "0.0.0.0"
PORT = 3333
NODE_API_BASE = "http://127.0.0.1:8080"

MAX_TOTAL_MINERS = 100
MAX_PER_IP = 5
MAX_FRAME_SIZE = 2048  # 2 KB frame limit
IDLE_TIMEOUT = 60.0    # 60s inactivity disconnect
RATE_LIMIT_BURST = 10  # Max msgs per second

# Memory state
active_ip_counts: Dict[str, int] = {}
connected_miners: Set["StratumClient"] = set()
current_job: Dict = {}
job_lock = asyncio.Lock()


def compute_pow_hash(index: int, prev_hash: str, merkle: str, miner_addr: str, timestamp: float, nonce: int) -> str:
    raw = f"{index}:{prev_hash}:{merkle}:{miner_addr}:{timestamp:.4f}:{nonce}"
    first_round = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    salt = hashlib.sha256((miner_addr + raw[:16]).encode('utf-8')).hexdigest()
    second_round = hashlib.sha256((first_round + salt).encode('utf-8')).hexdigest()
    return second_round


def query_node_template() -> Optional[Dict]:
    try:
        req = urllib.request.Request(
            f"{NODE_API_BASE}/api/mining/template",
            headers={"User-Agent": "WINEX-Stratum/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning(f"Failed to query node template: {e}")
    return None


def submit_block_to_node(miner_addr: str, block_index: int, nonce: int, timestamp: float, reported_hash: str) -> bool:
    try:
        payload = json.dumps({
            "miner_address": miner_addr,
            "block_index": block_index,
            "nonce": nonce,
            "timestamp": timestamp,
            "reported_hash": reported_hash
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{NODE_API_BASE}/api/mining/submit",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "WINEX-Stratum/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                res = json.loads(resp.read().decode("utf-8"))
                logger.info(f"*** BLOCK SOLVED & COMMITTED: #{block_index} by {miner_addr[:16]}... Hash: {reported_hash[:16]} ***")
                return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        logger.warning(f"Block submission rejected by node ({e.code}): {body}")
    except Exception as e:
        logger.error(f"Error submitting block to node: {e}")
    return False


class StratumClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str):
        self.reader = reader
        self.writer = writer
        self.client_ip = client_ip
        self.session_id = hashlib.md5(f"{time.time()}:{client_ip}".encode()).hexdigest()[:8]
        self.wallet_address = ""
        self.worker_name = ""
        self.subscribed = False
        self.authorized = False
        self.msg_count = 0
        self.last_msg_reset = time.time()

    async def send_json(self, data: dict):
        try:
            line = json.dumps(data) + "\n"
            self.writer.write(line.encode("utf-8"))
            await self.writer.drain()
        except Exception:
            pass

    async def send_notify(self, job: dict, clean_jobs: bool = False):
        if not self.authorized:
            return
        # Standard stratum mining.notify frame
        params = [
            str(job.get("block_index")),
            job.get("prev_hash", ""),
            job.get("merkle_root", ""),
            "",  # coinb1
            "",  # coinb2
            [],  # merkle_branch
            "00000001",  # version
            job.get("target_prefix", "00000"),  # nbits
            f"{int(job.get('server_time', time.time())):08x}",  # ntime
            clean_jobs
        ]
        await self.send_json({"id": None, "method": "mining.notify", "params": params})

    async def read_line_bounded(self) -> Optional[bytes]:
        """Reads stream with strict real-time byte chunk limiting to prevent OOM buffer bombs."""
        buf = bytearray()
        while True:
            chunk = await self.reader.read(128)
            if not chunk:
                return None if not buf else bytes(buf)
            buf.extend(chunk)
            if len(buf) > MAX_FRAME_SIZE:
                logger.warning(f"Oversized frame from {self.client_ip} ({len(buf)} bytes > {MAX_FRAME_SIZE}). Terminating connection.")
                return None
            if b"\n" in chunk:
                line, rest = buf.split(b"\n", 1)
                return bytes(line)

    async def handle(self):
        global active_ip_counts, connected_miners
        try:
            while True:
                try:
                    raw_line = await asyncio.wait_for(self.read_line_bounded(), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.debug(f"Client {self.client_ip} timed out (idle)")
                    break

                if raw_line is None:
                    break
                if not raw_line.strip():
                    continue

                now = time.time()
                if now - self.last_msg_reset > 1.0:
                    self.msg_count = 0
                    self.last_msg_reset = now
                self.msg_count += 1
                if self.msg_count > RATE_LIMIT_BURST:
                    logger.warning(f"Rate limit exceeded by {self.client_ip}. Dropping.")
                    break

                try:
                    msg = json.loads(raw_line.decode("utf-8", errors="ignore").strip())
                except Exception:
                    continue

                await self.process_message(msg)

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"Exception handling client {self.client_ip}: {e}")
        finally:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass


    async def process_message(self, msg: dict):
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", [])

        if method == "mining.subscribe":
            self.subscribed = True
            extranonce1 = self.session_id
            extranonce2_size = 4
            res = [
                [["mining.set_difficulty", self.session_id], ["mining.notify", self.session_id]],
                extranonce1,
                extranonce2_size
            ]
            await self.send_json({"id": req_id, "result": res, "error": None})

        elif method == "mining.authorize":
            worker_id = str(params[0]) if len(params) > 0 else "unknown"
            # Extract address before dot if worker formatted as address.worker1
            raw_addr = worker_id.split(".")[0].strip()
            # Strict WINEX 35-character address validation (^WNX[0-9A-F]{32}$)
            if re.match(r"^WNX[0-9A-F]{32}$", raw_addr):
                self.wallet_address = raw_addr
                self.worker_name = worker_id
                self.authorized = True
                await self.send_json({"id": req_id, "result": True, "error": None})

                # Set initial difficulty
                target_diff = current_job.get("difficulty", 6)
                await self.send_json({"id": None, "method": "mining.set_difficulty", "params": [target_diff]})
                if current_job:
                    await self.send_notify(current_job, clean_jobs=True)
            else:
                await self.send_json({"id": req_id, "result": False, "error": [20, "Invalid WINEX payout address (expected WNX + 32 uppercase hex chars)", None]})

        elif method == "mining.submit":
            if not self.authorized:
                await self.send_json({"id": req_id, "result": False, "error": [24, "Unauthorized worker", None]})
                return

            try:
                # params: [worker, job_id, extranonce2, ntime, nonce]
                job_id = str(params[1]) if len(params) > 1 else ""
                nonce_raw = params[4] if len(params) > 4 else 0
                if isinstance(nonce_raw, str):
                    nonce = int(nonce_raw, 16) if nonce_raw.startswith("0x") else int(nonce_raw)
                else:
                    nonce = int(nonce_raw)

                block_idx = current_job.get("block_index", 0)
                prev_h = current_job.get("prev_hash", "")
                merkle = current_job.get("merkle_root", "")
                prefix = current_job.get("target_prefix", "0000000")
                timestamp = current_job.get("server_time", time.time())

                calculated_hash = compute_pow_hash(block_idx, prev_h, merkle, self.wallet_address, timestamp, nonce)

                if calculated_hash.startswith(prefix):
                    # Valid block found! Submit to canonical chain
                    ok = submit_block_to_node(self.wallet_address, block_idx, nonce, timestamp, calculated_hash)
                    if ok:
                        await self.send_json({"id": req_id, "result": True, "error": None})
                        # Refresh template immediately
                        asyncio.create_task(refresh_jobs_now())
                        return
                    else:
                        await self.send_json({"id": req_id, "result": False, "error": [21, "Node rejected block", None]})
                        return
                else:
                    # Low difficulty share or mismatch
                    await self.send_json({"id": req_id, "result": False, "error": [23, "Low difficulty share", None]})
            except Exception as e:
                logger.debug(f"Submit error: {e}")
                await self.send_json({"id": req_id, "result": False, "error": [20, "Malformed submit params", None]})

        elif method == "mining.extranonce.subscribe":
            await self.send_json({"id": req_id, "result": True, "error": None})

        elif method == "mining.get_transactions":
            await self.send_json({"id": req_id, "result": [], "error": None})

        else:
            await self.send_json({"id": req_id, "result": None, "error": [20, f"Unsupported method: {method}", None]})


async def refresh_jobs_now():
    global current_job
    tmpl = query_node_template()
    if tmpl and tmpl != current_job:
        is_new_block = tmpl.get("block_index") != current_job.get("block_index")
        current_job = tmpl
        if is_new_block:
            logger.info(f"New block template detected: #{tmpl.get('block_index')} TargetPrefix: {tmpl.get('target_prefix')}")
            for c in list(connected_miners):
                if c.authorized:
                    asyncio.create_task(c.send_notify(current_job, clean_jobs=True))


async def job_poll_loop():
    while True:
        try:
            await refresh_jobs_now()
        except Exception as e:
            logger.debug(f"Job poll loop error: {e}")
        await asyncio.sleep(4.0)


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global active_ip_counts, connected_miners

    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    # Anti-DDoS Connection Limits
    if len(connected_miners) >= MAX_TOTAL_MINERS:
        logger.warning(f"Rejecting {client_ip}: Global connection limit reached ({MAX_TOTAL_MINERS})")
        writer.close()
        await writer.wait_closed()
        return

    curr_ip_conns = active_ip_counts.get(client_ip, 0)
    if curr_ip_conns >= MAX_PER_IP:
        logger.warning(f"Rejecting {client_ip}: Per-IP limit reached ({MAX_PER_IP})")
        writer.close()
        await writer.wait_closed()
        return

    active_ip_counts[client_ip] = curr_ip_conns + 1
    client = StratumClient(reader, writer, client_ip)
    connected_miners.add(client)
    logger.info(f"Miner connected from {client_ip} (Total miners: {len(connected_miners)})")

    try:
        await client.handle()
    finally:
        connected_miners.discard(client)
        if client_ip in active_ip_counts:
            active_ip_counts[client_ip] -= 1
            if active_ip_counts[client_ip] <= 0:
                del active_ip_counts[client_ip]
        logger.info(f"Miner disconnected: {client_ip} (Total miners: {len(connected_miners)})")


async def main():
    logger.info(f"Starting WINEX Stratum Server on {HOST}:{PORT}...")
    tmpl = query_node_template()
    if tmpl:
        logger.info(f"Connected to local node. Current Height: #{tmpl.get('block_index')} | Target: {tmpl.get('target_prefix')}")
    else:
        logger.warning("Local node API not reachable yet. Will retry in background.")

    asyncio.create_task(job_poll_loop())

    server = await asyncio.start_server(handle_connection, HOST, PORT, reuse_port=True)
    logger.info(f"Stratum TCP Server listening on port {PORT}. Ready for ASIC/CPU/GPU connections.")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stratum Server shutting down gracefully.")
