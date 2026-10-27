import os
import sys
import time
import base64
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse, Response, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from winex_core import (
    WinexBlockchain, MINING_POOL_INITIAL, INITIAL_BLOCK_REWARD, MINING_DIFFICULTY,
    HALVING_INTERVAL_BLOCKS, get_block_reward, sign_data
)

chain = WinexBlockchain()
BLOCK_REWARD = INITIAL_BLOCK_REWARD

app = FastAPI(title="WINEX Core Node", version="3.6.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://winexcoin.com",
        "https://www.winexcoin.com",
        "http://winexcoin.com",
        "http://www.winexcoin.com",
        "http://localhost",
        "http://127.0.0.1"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== PUBLIC OPEN PROTOCOL DOWNLOADS ====================
def check_download_auth(request: Request):
    """100% public decentralized downloads with zero passwords, accounts, or telemetry."""
    return True


API_RATE_LIMITS = {}

def check_api_rate_limit(ip: str, action: str, max_requests: int, window_sec: float) -> bool:
    now = time.time()
    if len(API_RATE_LIMITS) > 5000:
        API_RATE_LIMITS.clear()
    key = f"{ip}:{action}"
    history = API_RATE_LIMITS.get(key, [])
    history = [t for t in history if now - t < window_sec]
    if len(history) >= max_requests:
        API_RATE_LIMITS[key] = history
        return False
    history.append(now)
    API_RATE_LIMITS[key] = history
    return True

@app.middleware("http")
async def security_and_auth_gate(request: Request, call_next):
    # Enforce request body size limits to block OOM & HTTP flood attacks (both Content-Length and chunked)
    if request.method in ("POST", "PUT", "PATCH"):
        content_len = request.headers.get("content-length")
        if content_len:
            try:
                if int(content_len) > 2 * 1024 * 1024:
                    return Response(content="Payload Too Large", status_code=413)
            except ValueError:
                return Response(content="Bad Request", status_code=400)
        else:
            MAX_BODY = 2 * 1024 * 1024
            body_parts = []
            total_bytes = 0
            async for chunk in request.stream():
                total_bytes += len(chunk)
                if total_bytes > MAX_BODY:
                    return Response(content="Payload Too Large", status_code=413)
                body_parts.append(chunk)
            request._body = b"".join(body_parts)

    if request.method == "POST":
        # Only trust cf-connecting-ip if client connection originates from localhost proxy or trusted Cloudflare IP
        raw_remote = request.client.host if request.client else "unknown"
        if raw_remote in ("127.0.0.1", "::1", "localhost") and "cf-connecting-ip" in request.headers:
            client_ip = request.headers.get("cf-connecting-ip").strip()
        else:
            client_ip = raw_remote

        if not check_api_rate_limit(client_ip, request.url.path, max_requests=60, window_sec=60.0):
            return Response(content="Too Many Requests", status_code=429)

    # Public portal: All informational pages and APIs are completely public for users and Googlebot
    response = await call_next(request)

    # Standard security hardening headers for all requests
    if not request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: blob: data:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob: https:; "
        "media-src 'self' data: blob: https:; "
        "connect-src 'self' https: blob: data:;"
    )
    return response



# Cache Base64 Logo for zero-latency inlining
LOGO_B64 = ""
for p in [
    "/home/ubuntu/winex-node/assets/winex_logo_128.png",
    "/home/ubuntu/winex-node/downloads/winex_logo_128.png",
    "/home/ubuntu/winex-node/winex_logo_128.png",
    "/home/tux/Masaüstü/WINEX_Server_Code/assets/winex_logo_128.png",
    "/home/tux/Masaüstü/WINEX_Server_Code/winex_logo_128.png",
    "/home/ubuntu/winex-node/assets/winex_logo.png",
    "/home/ubuntu/winex-node/downloads/winex_logo.png",
    "/home/ubuntu/winex-node/winex_logo.png",
    "/home/tux/Masaüstü/WINEX_Server_Code/winex_logo.png"
]:
    if os.path.exists(p):
        try:
            with open(p, "rb") as f:
                LOGO_B64 = base64.b64encode(f.read()).decode("utf-8")
            break
        except Exception:
            pass

class TxRequest(BaseModel):
    sender: str
    recipient: str
    amount: float
    fee: float = 0.0
    timestamp: Optional[float] = None
    public_key: str
    signature: str

class MineSubmitRequest(BaseModel):
    miner_address: str
    block_index: int
    nonce: int
    timestamp: float
    hash: Optional[str] = None
    reported_hash: Optional[str] = None

class PeerRegisterRequest(BaseModel):
    peer_url: str

class BlockGossipRequest(BaseModel):
    block_index: int
    miner_address: str
    nonce: int
    timestamp: float
    hash: str

class TxGossipRequest(BaseModel):
    sender: str
    recipient: str
    amount: float
    fee: float
    pub_key: str
    signature: str
    timestamp: Optional[float] = None

@app.get("/api/status")
@app.get("/api/state")
@app.get("/stats")
def get_status():
    height = chain.get_height()
    pool_rem = chain.get_pool_remaining()
    mined_so_far = MINING_POOL_INITIAL - pool_rem

    cur = chain.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM mempool")
    mempool_count = cur.fetchone()[0]

    return {
        "coin_name": "WINEX",
        "symbol": "WNX",
        "mining_pool_available": round(pool_rem, 4),
        "pool_remaining": round(pool_rem, 4),
        "mined_circulation": round(mined_so_far, 4),
        "block_height": height,
        "mempool_tx_count": mempool_count,
        "block_reward": get_block_reward(height + 1),
        "difficulty": MINING_DIFFICULTY,
        "peer_count": len(chain.get_peers())
    }

@app.get("/api/blocks")
def get_blocks(limit: int = 20):
    limit = max(1, min(100, int(limit)))
    return chain.get_latest_blocks(limit)

@app.get("/api/transactions")
@app.get("/api/transactions/recent")
def get_transactions(limit: int = 30):
    limit = max(1, min(100, int(limit)))
    return chain.get_latest_transactions(limit)

@app.get("/api/balance/{address}")
def get_balance(address: str):
    bal = chain.get_balance(address)
    return {"address": address, "balance": bal}

@app.get("/api/block/{block_id}")
def get_block_detail(block_id: str):
    blk = chain.get_block_by_id(block_id)
    if not blk:
        raise HTTPException(status_code=404, detail="Block not found")
    return blk

@app.get("/api/tx/{tx_id}")
@app.get("/api/transaction/{tx_id}")
def get_tx_detail(tx_id: str):
    tx = chain.get_transaction_by_id(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return tx

@app.get("/api/address/{address}")
@app.get("/api/address/{address}/txs")
def get_address_detail(address: str, limit: int = 50):
    return chain.get_address_info(address, limit)

@app.get("/api/supply")
@app.get("/api/circulating_supply")
def get_supply_metrics():
    pool_rem = chain.get_pool_remaining()
    mined = round(MINING_POOL_INITIAL - pool_rem, 6)
    return {
        "max_supply": MINING_POOL_INITIAL,
        "circulating_supply": mined,
        "unmined_pool_remaining": round(pool_rem, 6),
        "initial_block_reward": INITIAL_BLOCK_REWARD,
        "current_block_reward": get_block_reward(chain.get_height() + 1),
        "halving_interval": HALVING_INTERVAL_BLOCKS
    }

@app.get("/api/total_supply/plain")
@app.get("/api/supply/total/plain")
def get_total_supply_plain():
    return PlainTextResponse("12100000.0")

@app.get("/api/circulating_supply/plain")
@app.get("/api/supply/circulating/plain")
def get_circulating_supply_plain():
    pool_rem = chain.get_pool_remaining()
    mined = round(MINING_POOL_INITIAL - pool_rem, 6)
    return PlainTextResponse(str(mined))

@app.get("/api/max_supply/plain")
@app.get("/api/supply/max/plain")
def get_max_supply_plain():
    return PlainTextResponse("12100000.0")

@app.post("/rpc")
@app.post("/api/rpc")
async def json_rpc_handler(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}, status_code=400)

    req_id = payload.get("id", 1)
    method = (payload.get("method") or "").strip().lower()
    params = payload.get("params") or []

    def rpc_ok(res):
        return {"jsonrpc": "2.0", "result": res, "id": req_id}

    def rpc_err(code: int, msg: str):
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": code, "message": msg}, "id": req_id}, status_code=200)

    try:
        if method in ("getblockcount", "getheight"):
            return rpc_ok(chain.get_height())

        elif method == "getbestblockhash":
            blks = chain.get_latest_blocks(1)
            return rpc_ok(blks[0]["hash"] if blks else "")

        elif method == "getblockhash":
            if not params:
                return rpc_err(-32602, "Missing height parameter")
            blk = chain.get_block_by_id(str(params[0]))
            if not blk:
                return rpc_err(-5, "Block height out of range")
            return rpc_ok(blk["hash"])

        elif method == "getblock":
            if not params:
                return rpc_err(-32602, "Missing block hash or height parameter")
            blk = chain.get_block_by_id(str(params[0]))
            if not blk:
                return rpc_err(-5, "Block not found")
            return rpc_ok(blk)

        elif method in ("gettransaction", "getrawtransaction"):
            if not params:
                return rpc_err(-32602, "Missing tx_id parameter")
            tx = chain.get_transaction_by_id(str(params[0]))
            if not tx:
                return rpc_err(-5, "No such mempool or blockchain transaction")
            return rpc_ok(tx)

        elif method == "getbalance":
            if not params:
                return rpc_err(-32602, "Missing address parameter")
            addr = str(params[0]).strip()
            info = chain.get_address_info(addr, limit=1)
            return rpc_ok({
                "address": addr,
                "confirmed": info["confirmed_balance"],
                "unconfirmed": info["unconfirmed_incoming"],
                "spendable": info["spendable_balance"]
            })

        elif method in ("getaddresshistory", "listtransactions"):
            if not params:
                return rpc_err(-32602, "Missing address parameter")
            addr = str(params[0]).strip()
            lim = int(params[1]) if len(params) > 1 else 50
            return rpc_ok(chain.get_address_info(addr, limit=lim))

        elif method == "validateaddress":
            if not params:
                return rpc_err(-32602, "Missing address parameter")
            addr = str(params[0]).strip()
            valid = chain.validate_address(addr)
            return rpc_ok({"isvalid": valid, "address": addr if valid else ""})

        elif method == "sendrawtransaction":
            tx_obj = params[0] if params and isinstance(params[0], dict) else (payload.get("params") if isinstance(payload.get("params"), dict) else None)
            if not tx_obj:
                return rpc_err(-32602, "Expected signed transaction object in params[0]")
            ok, res = chain.add_transaction_to_mempool(
                sender=str(tx_obj.get("sender", "")),
                recipient=str(tx_obj.get("recipient", "")),
                amount=float(tx_obj.get("amount", 0)),
                fee=float(tx_obj.get("fee", 0)),
                pub_key=str(tx_obj.get("public_key", "")),
                signature=str(tx_obj.get("signature", "")),
                timestamp=tx_obj.get("timestamp")
            )
            if not ok:
                return rpc_err(-25, res)
            return rpc_ok(res)

        elif method == "getmininginfo":
            return rpc_ok(chain.get_mining_template())

        elif method in ("getnetworkinfo", "getinfo"):
            return rpc_ok(get_status())

        elif method == "getpeerinfo":
            return rpc_ok([{"addr": p} for p in chain.get_peers()])

        else:
            return rpc_err(-32601, f"Method '{method}' not found")
    except Exception as e:
        return rpc_err(-32603, str(e))

@app.post("/api/tx/send")
@app.post("/api/transaction/send")
def send_transaction(req: TxRequest):
    import math
    if math.isnan(req.amount) or math.isinf(req.amount) or req.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid transfer amount.")
    if math.isnan(req.fee) or math.isinf(req.fee) or req.fee < 0 or req.fee > 1000:
        raise HTTPException(status_code=400, detail="Invalid transaction fee.")
    if not req.public_key or not req.signature:
        raise HTTPException(status_code=400, detail="Transaction signature (public_key and signature) required.")
    pub_key = req.public_key.strip()
    sig = req.signature.strip()

    success, result = chain.add_transaction_to_mempool(
        sender=req.sender,
        recipient=req.recipient,
        amount=req.amount,
        fee=req.fee,
        pub_key=pub_key,
        signature=sig,
        timestamp=req.timestamp
    )
    if not success:
        raise HTTPException(status_code=400, detail=result)
    return {"status": "ok", "success": True, "tx_id": result, "message": "Transaction submitted to mempool."}

@app.get("/api/mining/template")
def get_mining_template():
    return chain.get_mining_template()

@app.post("/api/mining/submit")
def submit_block(req: MineSubmitRequest):
    block_hash = (req.hash or req.reported_hash or "").strip()
    if not block_hash:
        raise HTTPException(status_code=400, detail="Hash field is required.")
    success, result = chain.verify_and_submit_block(
        miner_address=req.miner_address,
        block_index=req.block_index,
        nonce=req.nonce,
        timestamp=req.timestamp,
        reported_hash=block_hash
    )
    if not success:
        raise HTTPException(status_code=400, detail=result)
    actual_reward = get_block_reward(req.block_index)
    return {
        "status": "ok",
        "success": True,
        "block_index": req.block_index,
        "block_hash": result,
        "reward": actual_reward,
        "message": "Block verified and committed to canonical chain."
    }

# ==================== P2P DECENTRALIZED PROTOCOL ====================

@app.get("/p2p/peers")
@app.get("/api/p2p/peers")
@app.get("/api/peers")
def get_peers():
    return {"peers": chain.get_peers()}

@app.post("/p2p/register")
@app.post("/api/p2p/register")
def register_peer(req: PeerRegisterRequest, request: Request):
    client_host = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")
    chain.add_peer(req.peer_url, client_ip=client_host)
    return {"status": "ok", "registered": req.peer_url, "your_ip": client_host}

@app.get("/p2p/blocks_export")
def export_blocks(from_index: int = 0, limit: int = 100):
    limit = max(1, min(100, int(limit)))
    from_index = max(0, int(from_index))
    cur = chain.conn.cursor()
    cur.execute("SELECT * FROM blocks WHERE block_index >= ? ORDER BY block_index ASC LIMIT ?", (from_index, limit))
    return [dict(r) for r in cur.fetchall()]

@app.post("/p2p/receive_block")
def receive_gossiped_block(req: BlockGossipRequest):
    cur = chain.conn.cursor()
    cur.execute("SELECT block_index FROM blocks WHERE hash = ?", (req.hash,))
    if cur.fetchone():
        return {"status": "already_have"}
    
    success, result = chain.verify_and_submit_block(
        miner_address=req.miner_address,
        block_index=req.block_index,
        nonce=req.nonce,
        timestamp=req.timestamp,
        reported_hash=req.hash
    )
    return {"status": "accepted" if success else "rejected", "result": result}

@app.post("/p2p/receive_tx")
def receive_gossiped_tx(req: TxGossipRequest):
    success, result = chain.add_transaction_to_mempool(
        sender=req.sender,
        recipient=req.recipient,
        amount=req.amount,
        fee=req.fee,
        pub_key=req.pub_key,
        signature=req.signature,
        timestamp=req.timestamp
    )
    return {"status": "accepted" if success else "rejected", "tx_id": result}

# ==================== SEARCH ENGINE OPTIMIZATION (SEO) ====================

@app.get("/robots.txt", response_class=PlainTextResponse)
def get_robots_txt():
    return """User-agent: *
Allow: /
Disallow: /api/
Disallow: /p2p/

Sitemap: https://winexcoin.com/sitemap.xml
"""

@app.get("/sitemap.xml")
def get_sitemap_xml():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://winexcoin.com/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/tokenomics</loc>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/architecture</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/roadmap</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/whitepaper</loc>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/download</loc>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/explorer</loc>
    <changefreq>always</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/telemetry</loc>
    <changefreq>always</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/legal</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/contact</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/terms</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/privacy</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://winexcoin.com/about</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"""
    return Response(content=xml_content, media_type="application/xml")

# ==================== STATIC DOWNLOADS ====================

@app.get("/favicon.ico")
@app.get("/download/favicon.ico")
def get_favicon():
    for p in ["/home/ubuntu/winex-node/downloads/favicon.ico", "/home/tux/winex-wallet/favicon.ico"]:
        if os.path.exists(p):
            return FileResponse(p, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="Favicon not found")

@app.get("/logo.png")
@app.get("/download/winex_logo_128.png")
def get_logo_128():
    for p in ["/home/ubuntu/winex-node/downloads/winex_logo_128.png", "/home/tux/winex-wallet/winex_logo_128.png", "/home/ubuntu/winex-node/downloads/winex_logo.png"]:
        if os.path.exists(p):
            return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/download/winex_logo.png")
def get_logo_full():
    for p in ["/home/ubuntu/winex-node/downloads/winex_logo.png", "/home/tux/winex-wallet/winex_logo.png"]:
        if os.path.exists(p):
            return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/download/WINEX-Wallet.zip")
@app.get("/downloads/WINEX-Wallet.zip")
@app.get("/download/WINEX_Windows_Package.zip")
@app.get("/downloads/WINEX_Windows_Package.zip")
@app.get("/download/WINEX_Windows_Suite.zip")
@app.get("/downloads/WINEX_Windows_Suite.zip")
def download_wallet_pkg(request: Request):
    check_download_auth(request)
    return RedirectResponse(
        url="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Windows_Suite.zip",
        status_code=302
    )

@app.get("/download/WINEX_Windows_Setup.zip")
@app.get("/downloads/WINEX_Windows_Setup.zip")
def download_windows_setup_zip(request: Request):
    check_download_auth(request)
    return RedirectResponse(
        url="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Windows_Setup.zip",
        status_code=302
    )

@app.get("/download/WINEX_Setup.exe")
@app.get("/downloads/WINEX_Setup.exe")
def download_setup_exe(request: Request):
    check_download_auth(request)
    return RedirectResponse(
        url="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Setup.exe",
        status_code=302
    )

@app.get("/download/WINEX_Wallet.exe")
@app.get("/downloads/WINEX_Wallet.exe")
def download_wallet_exe(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Wallet.exe", "/home/tux/winex-wallet/WINEX_Wallet.exe"]:
        if os.path.exists(p):
            return FileResponse(
                p,
                filename="WINEX_Wallet.exe",
                media_type="application/vnd.microsoft.portable-executable",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0"
                }
            )
    raise HTTPException(status_code=404, detail="Wallet exe not found")

@app.get("/download/WINEX_Miner_Windows.zip")
@app.get("/downloads/WINEX_Miner_Windows.zip")
def download_miner_windows_zip(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Miner_Windows.zip"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Miner_Windows.zip", media_type="application/zip")
    raise HTTPException(status_code=404, detail="Miner Windows zip not found")

@app.get("/download/WINEX_Windows_Wallet.zip")
@app.get("/downloads/WINEX_Windows_Wallet.zip")
def download_windows_wallet_zip(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Windows_Wallet.zip"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Windows_Wallet.zip", media_type="application/zip")
    raise HTTPException(status_code=404, detail="Windows Wallet zip not found")

@app.get("/download/WINEX_Miner.exe")
@app.get("/downloads/WINEX_Miner.exe")
def download_miner_exe(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Miner.exe", "/home/tux/winex-wallet/WINEX_Miner.exe"]:
        if os.path.exists(p):
            return FileResponse(
                p,
                filename="WINEX_Miner.exe",
                media_type="application/vnd.microsoft.portable-executable",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0"
                }
            )
    raise HTTPException(status_code=404, detail="Miner exe not found")

@app.get("/download/WINEX_Node.exe")
@app.get("/downloads/WINEX_Node.exe")
def download_node_exe(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Node.exe", "/home/tux/winex-wallet/WINEX_Node.exe"]:
        if os.path.exists(p):
            return FileResponse(
                p,
                filename="WINEX_Node.exe",
                media_type="application/vnd.microsoft.portable-executable",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0"
                }
            )
    raise HTTPException(status_code=404, detail="Node exe not found")

@app.get("/download/WINEX_Node_Linux")
@app.get("/downloads/WINEX_Node_Linux")
def download_node_linux(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Node_Linux", "/home/tux/winex-wallet/WINEX_Node_Linux"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Node_Linux", media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="Linux node binary not found")

@app.get("/download/WINEX_Linux_Suite.zip")
@app.get("/downloads/WINEX_Linux_Suite.zip")
@app.get("/download/WINEX_Linux_Package.zip")
@app.get("/downloads/WINEX_Linux_Package.zip")
def download_linux_zip(request: Request):
    check_download_auth(request)
    return RedirectResponse(
        url="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Linux_Suite.zip",
        status_code=302
    )

@app.get("/download/WINEX_macOS_Suite.zip")
@app.get("/downloads/WINEX_macOS_Suite.zip")
def download_macos_zip(request: Request):
    check_download_auth(request)
    return RedirectResponse(
        url="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_macOS_Suite.zip",
        status_code=302
    )

@app.get("/download/WINEX_Linux_Package.tar.gz")
@app.get("/downloads/WINEX_Linux_Package.tar.gz")
def download_linux_package(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Linux_Package.tar.gz", "/home/tux/winex-wallet/WINEX_Linux_Package.tar.gz"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Linux_Package.tar.gz", media_type="application/gzip")
    raise HTTPException(status_code=404, detail="Linux package not found")

@app.get("/download/WINEX_Wallet_Linux")
@app.get("/downloads/WINEX_Wallet.AppImage")
async def download_wallet_appimage(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Wallet.AppImage", "/home/ubuntu/winex-node/releases/WINEX_Wallet.AppImage"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Wallet.AppImage", media_type="application/x-executable")
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/downloads/WINEX_Wallet_Linux")
def download_wallet_linux(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Wallet_Linux", "/home/tux/winex-wallet/WINEX_Wallet_Linux"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Wallet_Linux", media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="Linux wallet binary not found")

@app.get("/download/WINEX_Miner_Linux")
@app.get("/downloads/WINEX_Miner_Linux")
def download_miner_linux(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/WINEX_Miner_Linux", "/home/tux/winex-wallet/WINEX_Miner_Linux"]:
        if os.path.exists(p):
            return FileResponse(p, filename="WINEX_Miner_Linux", media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="Linux miner binary not found")

@app.get("/install.sh")
@app.get("/download/install.sh")
@app.get("/downloads/install.sh")
@app.head("/downloads/install.sh")
@app.head("/download/install.sh")
@app.head("/install.sh")
def download_install_sh(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/install.sh", "/home/ubuntu/winex-node/install.sh", "/home/tux/Masaüstü/WINEX_Server_Code/install.sh"]:
        if os.path.exists(p):
            return FileResponse(p, filename="install.sh", media_type="text/x-shellscript")
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/install_mac.sh")
@app.get("/download/install_mac.sh")
@app.get("/downloads/install_mac.sh")
@app.head("/downloads/install_mac.sh")
@app.head("/download/install_mac.sh")
@app.head("/install_mac.sh")
def download_install_mac_sh(request: Request):
    check_download_auth(request)
    for p in ["/home/ubuntu/winex-node/downloads/install_mac.sh", "/home/ubuntu/winex-node/install_mac.sh", "/home/tux/Masaüstü/WINEX_Server_Code/install_mac.sh"]:
        if os.path.exists(p):
            return FileResponse(p, filename="install_mac.sh", media_type="text/x-shellscript")
    raise HTTPException(status_code=404, detail="File not found")

# ==================== PUBLIC 3D MODEL & STUDIO ASSET ENDPOINTS ====================

ALLOWED_PUBLIC_ASSETS = {
    "w_coin.glb": "model/gltf-binary",
    "01_front.png": "image/png",
    "02_back.png": "image/png",
    "03_three_quarter.png": "image/png",
    "04_edge_closeup.png": "image/png",
    "w_coin_turntable.mp4": "video/mp4",
    "winex_logo.png": "image/png",
    "winex_logo_128.png": "image/png",
    "favicon.ico": "image/x-icon",
    "blockspot-logo.png": "image/png",
}

@app.get("/assets/{asset_name}")
@app.head("/assets/{asset_name}")
def get_public_3d_asset(asset_name: str):
    if asset_name not in ALLOWED_PUBLIC_ASSETS:
        raise HTTPException(status_code=404, detail="Asset not found")
    mime = ALLOWED_PUBLIC_ASSETS[asset_name]
    for base_dir in [
        "/home/ubuntu/winex-node/assets",
        "/home/tux/Masaüstü/WINEX_Server_Code/assets",
        "/home/tux/.gemini/antigravity/scratch/w_coin/export",
        "/home/tux/.gemini/antigravity/scratch/w_coin/renders",
    ]:
        p = os.path.join(base_dir, asset_name)
        if os.path.exists(p):
            return FileResponse(
                p,
                media_type=mime,
                headers={"Cache-Control": "public, max-age=86400"}
            )
    raise HTTPException(status_code=404, detail="Asset file missing")

# ==================== SHARED LAYOUT & IMPECCABLE SWISS LEDGER DESIGN SYSTEM ====================

def render_layout(title: str, active_tab: str, content: str) -> str:
    if title == "Overview":
        page_seo_title = "WINEX (WNX) — Sovereign Proof-of-Work Layer-1 Protocol"
    else:
        page_seo_title = f"{title} | WINEX (WNX) — Sovereign Proof-of-Work Protocol"

    logo_src = f"data:image/png;base64,{LOGO_B64}" if LOGO_B64 else "/logo.png"

    nav_items = [
        ("/", "Overview", "overview"),
        ("/tokenomics", "Tokenomics", "tokenomics"),
        ("/whitepaper", "Whitepaper", "whitepaper"),
        ("/explorer", "Explorer", "explorer"),
        ("/download", "Download", "download"),
    ]

    nav_links_html = "".join([
        f'<a href="{url}" class="{"active" if active_tab == key else ""}">{label}</a>'
        for url, label, key in nav_items
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_seo_title}</title>
<meta name="description" content="WINEX (WNX) is an autonomous, open-source Layer-1 Proof-of-Work cryptocurrency protocol. Double SHA-256 consensus, deterministic block subsidy, 125,000-block halving epochs. Zero affiliation with Winex Markets forex.">
<meta name="keywords" content="winex, winex coin, winexcoin, WNX, proof of work layer-1, SHA-256 mining, non-custodial wallet, decentralized cryptocurrency, blockchain explorer">
<meta name="author" content="WINEX Core Protocol">
<meta name="robots" content="index, follow">
<meta name="disambiguation" content="WINEX (WNX) is an independent open-source Layer-1 blockchain protocol. It is NOT affiliated with 'Winex Markets' or any forex investment/brokerage platform.">
<link rel="canonical" href="https://winexcoin.com">
<meta property="og:title" content="{page_seo_title}">
<meta property="og:description" content="Sovereign Layer-1 Proof-of-Work protocol. Burned admin keys, deflationary emission model, and embedded full node client suite.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://winexcoin.com">
<meta property="og:site_name" content="WINEX Protocol">
<meta property="og:image" content="https://winexcoin.com/download/winex_logo_128.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{page_seo_title}">
<meta name="twitter:description" content="Autonomous Layer-1 Proof-of-Work cryptocurrency protocol with deterministic halving schedule and embedded P2P node.">
<meta name="twitter:image" content="https://winexcoin.com/download/winex_logo_128.png">
<link rel="icon" type="image/x-icon" href="/favicon.ico?v=12">
<link rel="icon" type="image/png" sizes="128x128" href="/download/winex_logo_128.png?v=12">
<link rel="apple-touch-icon" href="/download/winex_logo_128.png?v=12">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@graph": [
    {{
      "@type": "WebSite",
      "name": "WINEX (WNX) Core Protocol",
      "alternateName": ["WINEX Coin", "WNX", "WINEX Layer-1"],
      "url": "https://winexcoin.com",
      "description": "Autonomous open-source Proof-of-Work Layer-1 blockchain protocol."
    }},
    {{
      "@type": "Organization",
      "name": "WINEX Protocol Open Source Community",
      "url": "https://winexcoin.com",
      "email": "support@winexcoin.com",
      "description": "Decentralized open-source developer collective maintaining the WINEX (WNX) Layer-1 PoW blockchain protocol.",
      "disambiguatingDescription": "WINEX (WNX) is an independent cryptographic Layer-1 Proof-of-Work protocol. It is NOT affiliated with 'Winex Markets' or any forex/investment platform."
    }},
    {{
      "@type": "SoftwareApplication",
      "name": "WINEX Core Sovereign Suite",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "Windows, Linux, macOS",
      "license": "https://opensource.org/licenses/MIT",
      "description": "Non-custodial open-source Layer-1 Proof-of-Work desktop wallet, validator node, and hybrid PoW mining suite.",
      "offers": {{
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD"
      }}
    }}
  ]
}}
</script>

<style>
  :root {{
    --bg-canvas: #06070a;
    --bg-surface: rgba(12, 15, 22, 0.88);
    --bg-elevated: rgba(18, 23, 34, 0.94);
    --border-line: #1e2536;
    --border-strong: #2e384f;
    --text-main: #f8fafc;
    --text-body: #cbd5e1;
    --text-muted: #94a3b8;
    --accent-primary: #10b981;
    --accent-secondary: #38bdf8;
    --font-sans: 'Sora', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
  }}

  *, *::before, *::after {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }}

  ::selection {{
    background: var(--accent-primary);
    color: #040608;
  }}

  ::-webkit-scrollbar {{
    width: 8px;
    height: 8px;
  }}
  ::-webkit-scrollbar-track {{
    background: var(--bg-canvas);
  }}
  ::-webkit-scrollbar-thumb {{
    background: var(--border-strong);
  }}

  a:focus-visible, button:focus-visible, input:focus-visible {{
    outline: 2px solid var(--accent-secondary);
    outline-offset: 2px;
  }}

  /* tsParticles (particles.js.org) Interactive Node Mesh Background */
  body {{
    background-color: #06080d;
    color: var(--text-main);
    font-family: var(--font-sans);
    font-size: 16px;
    line-height: 1.65;
    -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
    position: relative;
  }}

  #tsparticles {{
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    z-index: 0;
    pointer-events: none;
  }}

  header, main, footer {{
    position: relative;
    z-index: 1;
  }}

  h1, h2, .brand-title, .hero-headline {{
    color: var(--text-main);
    font-weight: 800;
    letter-spacing: -0.028em;
    line-height: 1.15;
  }}

  h3, h4 {{
    color: var(--text-main);
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.2;
  }}

  .mono {{
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
  }}

  .container {{
    max-width: 1220px;
    margin: 0 auto;
    padding: 0 28px;
  }}

  /* Structural Header */
  header {{
    position: sticky;
    top: 0;
    z-index: 1000;
    background: rgba(6, 7, 10, 0.90);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border-line);
  }}
  .nav-wrap {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 68px;
    gap: 24px;
  }}
  .nav-brand {{
    display: inline-flex;
    align-items: center;
    gap: 12px;
    text-decoration: none;
    color: var(--text-main);
  }}
  .nav-brand img {{
    width: 38px;
    height: 38px;
    object-fit: contain;
    display: block;
  }}
  .brand-title {{
    font-size: 18px;
    font-weight: 800;
    letter-spacing: -0.01em;
  }}
  .brand-ticker {{
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-muted);
    padding-left: 8px;
    border-left: 1px solid var(--border-line);
  }}

  .nav-links {{
    display: flex;
    align-items: center;
    gap: 28px;
    flex-wrap: wrap;
  }}
  .nav-links a {{
    color: var(--text-muted);
    text-decoration: none;
    font-size: 14px;
    font-weight: 500;
    padding: 6px 0;
    border-bottom: 2px solid transparent;
    transition: color 0.15s ease, border-color 0.15s ease;
  }}
  .nav-links a:hover {{
    color: var(--text-main);
  }}
  .nav-links a.active {{
    color: var(--text-main);
    border-bottom-color: var(--accent-primary);
  }}

  /* Architectural Controls */
  .btn-row {{
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
  }}
  .btn-primary {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 13px 24px;
    background: var(--text-main);
    color: #06070a;
    font-size: 14px;
    font-weight: 700;
    text-decoration: none;
    border: 1px solid var(--text-main);
    border-radius: 4px;
    transition: background-color 0.15s ease, border-color 0.15s ease;
    cursor: pointer;
  }}
  .btn-primary:hover {{
    background: #dbe4f0;
    border-color: #dbe4f0;
  }}
  .btn-secondary {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 13px 24px;
    background: var(--bg-surface);
    color: var(--text-main);
    font-size: 14px;
    font-weight: 600;
    text-decoration: none;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    transition: background-color 0.15s ease, border-color 0.15s ease;
  }}
  .btn-secondary:hover {{
    background: var(--bg-elevated);
    border-color: var(--accent-secondary);
  }}

  /* Shared Editorial & Ledger Primitives */
  .page-intro {{
    padding: 64px 0 44px;
    border-bottom: 1px solid var(--border-line);
    margin-bottom: 48px;
  }}
  .page-intro h1 {{
    font-size: clamp(2rem, 3.4vw, 2.85rem);
    margin-bottom: 16px;
    max-width: 24ch;
  }}
  .page-intro p {{
    font-size: 17px;
    color: var(--text-body);
    max-width: 66ch;
    line-height: 1.65;
  }}

  .ledger-strip {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--border-line);
    border: 1px solid var(--border-line);
    margin-bottom: 56px;
  }}
  @media (max-width: 900px) {{
    .ledger-strip {{ grid-template-columns: repeat(2, 1fr); }}
  }}
  @media (max-width: 540px) {{
    .ledger-strip {{ grid-template-columns: 1fr; }}
  }}
  .ledger-cell {{
    background: var(--bg-surface);
    padding: 24px 26px;
  }}
  .ledger-label {{
    font-size: 13px;
    font-weight: 500;
    color: var(--text-muted);
    margin-bottom: 8px;
  }}
  .ledger-value {{
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    font-size: 22px;
    font-weight: 700;
    color: var(--text-main);
  }}
  .ledger-note {{
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 6px;
  }}

  .editorial-section {{
    border-top: 1px solid var(--border-line);
  }}
  .editorial-row {{
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 40px;
    padding: 40px 0;
    border-bottom: 1px solid var(--border-line);
    align-items: start;
  }}
  @media (max-width: 820px) {{
    .editorial-row {{
      grid-template-columns: 1fr;
      gap: 16px;
    }}
  }}
  .editorial-title {{
    font-size: 20px;
    font-weight: 700;
    color: var(--text-main);
    margin-top: 0;
  }}
  .editorial-body {{
    max-width: 68ch;
    color: var(--text-body);
    font-size: 15.5px;
    line-height: 1.7;
  }}
  .editorial-body p + p {{
    margin-top: 14px;
  }}

  .table-wrap {{
    padding: 14px;
    border: 1px solid var(--border-line);
    background: var(--bg-surface);
    overflow-x: auto;
    margin-bottom: 56px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    font-size: 14px;
  }}
  th {{
    padding: 16px 22px;
    background: var(--bg-elevated);
    color: var(--text-main);
    font-weight: 600;
    font-size: 13px;
    border-bottom: 1px solid var(--border-line);
  }}
  td {{
    padding: 15px 22px;
    border-bottom: 1px solid var(--border-line);
    color: var(--text-body);
  }}
  tr:last-child td {{
    border-bottom: none;
  }}
  tr:hover td {{
    background: rgba(255, 255, 255, 0.015);
  }}

  /* Institutional Multi-Column Footer & Legal Disclosures */
  footer {{
    border-top: 1px solid var(--border-line);
    background: rgba(8, 10, 15, 0.94);
    margin-top: 96px;
    padding: 64px 0 48px;
    color: var(--text-muted);
    font-size: 14px;
  }}
  .footer-grid {{
    display: grid;
    grid-template-columns: 1.6fr 1fr 1fr 1fr;
    gap: 40px;
    padding-bottom: 44px;
    border-bottom: 1px solid var(--border-line);
  }}
  @media (max-width: 900px) {{
    .footer-grid {{
      grid-template-columns: 1fr 1fr;
    }}
  }}
  @media (max-width: 560px) {{
    .footer-grid {{
      grid-template-columns: 1fr;
    }}
  }}
  .footer-col-title {{
    font-size: 14px;
    font-weight: 600;
    color: var(--text-main);
    margin-bottom: 14px;
  }}
  .footer-nav {{
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .footer-nav a {{
    color: var(--text-muted);
    text-decoration: none;
    font-size: 14px;
    transition: color 0.15s ease;
  }}
  .footer-nav a:hover {{
    color: var(--text-main);
  }}
  .footer-legal-ledger {{
    padding-top: 32px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 28px;
    font-size: 13px;
    line-height: 1.65;
    color: var(--text-muted);
  }}
  @media (max-width: 820px) {{
    .footer-legal-ledger {{
      grid-template-columns: 1fr;
    }}
  }}
  .footer-legal-ledger strong {{
    color: var(--text-body);
    font-weight: 600;
  }}
  .footer-bottom {{
    margin-top: 28px;
    padding-top: 24px;
    border-top: 1px solid var(--border-line);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 14px;
    font-size: 13px;
    color: var(--text-muted);
  }}
</style>
</head>
<body>
<div id="tsparticles" aria-hidden="true"></div>

<header>
  <div class="container nav-wrap">
    <a href="/" class="nav-brand">
      <img src="{logo_src}" alt="WINEX">
      <span class="brand-title">WINEX</span>
      <span class="brand-ticker">WNX &bull; L1 PoW</span>
    </a>
    <nav class="nav-links">
      {nav_links_html}
      <a href="https://github.com/WinexCoin/winex-core" target="_blank" rel="noopener" class="nav-gh-pill" style="display:inline-flex; align-items:center; gap:6px; background:rgba(255,255,255,0.06); padding:6px 14px; border-radius:6px; border:1px solid var(--border-line); color:var(--text-main); font-size:13px; font-weight:600; text-decoration:none; margin-left:6px; transition:border-color 0.2s, background 0.2s;">
        <svg style="width:15px; height:15px;" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        GitHub
      </a>
      <a href="https://discord.gg/pq3HV4jS" target="_blank" rel="noopener" class="nav-discord-pill" style="display:inline-flex; align-items:center; gap:6px; background:rgba(88,101,242,0.15); padding:6px 14px; border-radius:6px; border:1px solid rgba(88,101,242,0.4); color:#5865F2; font-size:13px; font-weight:600; text-decoration:none; margin-left:6px; transition:border-color 0.2s, background 0.2s;">
        <svg style="width:15px; height:15px;" viewBox="0 0 127.14 96.36" fill="currentColor"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.86,53,48.83,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z"/></svg>
        Discord
      </a>
    </nav>
  </div>
</header>

<main class="container">
  {content}
</main>

<footer>
  <div class="container">
    <!-- Blockspot.io Official Verified Badge Strip -->
    <div style="background: rgba(14, 20, 32, 0.75); border: 1px solid rgba(80, 180, 255, 0.22); border-radius: 10px; padding: 18px 24px; margin-bottom: 40px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <a href="https://blockspot.io/coin/winex-wnx/" target="_blank" rel="noopener" style="display: flex; align-items: center;">
          <img src="/assets/blockspot-logo.png" alt="Blockspot.io" style="height: 32px; width: auto; object-fit: contain;">
        </a>
        <div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-weight: 700; color: #fff; font-size: 14px;">Blockspot.io Official Verified Asset</span>
            <span style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.4); font-size: 11px; padding: 2px 8px; border-radius: 20px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">✓ Verified Badge</span>
          </div>
          <div style="font-size: 13px; color: var(--text-muted); margin-top: 3px;">
            WINEX (WNX) protocol specifications, circulating supply, and halving mechanics are independently validated and tracked on <a href="https://blockspot.io/coin/winex-wnx/" target="_blank" rel="noopener" style="color: #5fa8e0; text-decoration: underline;">Blockspot.io</a>.
          </div>
        </div>
      </div>
      <a href="https://blockspot.io/coin/winex-wnx/" target="_blank" rel="noopener" class="btn-secondary" style="padding: 8px 18px; font-size: 13px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; white-space: nowrap;">
        Inspect Blockspot.io Listing &rarr;
      </a>
    </div>

    <div class="footer-grid">
      <div>
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:14px;">
          <img src="{logo_src}" alt="WINEX Logo" style="width:30px; height:30px; object-fit:contain;">
          <span style="font-weight:700; color:var(--text-main); font-size:15px;">WINEX (WNX) Core Protocol</span>
        </div>
        <p style="font-size:14px; color:var(--text-muted); line-height:1.65; max-width:38ch;">
          Autonomous, non-custodial Layer-1 Proof-of-Work blockchain engineered for mathematical scarcity, client-side SECP256k1 custody, and peer-to-peer mesh verification.
        </p>
        <div style="margin-top:16px; padding-top:12px; border-top:1px solid rgba(255,255,255,0.06); font-size:13px; display:flex; flex-direction:column; gap:8px;">
          <div>
            <span style="color:var(--text-main); font-weight:600;">Open Source Code:</span><br>
            <a href="https://github.com/WinexCoin/winex-core" target="_blank" rel="noopener" style="color:var(--accent-cyan); text-decoration:none; display:inline-flex; align-items:center; gap:6px; margin-top:2px;">
              <svg style="width:14px; height:14px;" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              github.com/WinexCoin/winex-core
            </a>
          </div>
          <div>
            <span style="color:var(--text-main); font-weight:600;">Official Support Desk:</span><br>
            <a href="mailto:support@winexcoin.com" style="color:var(--accent-secondary); text-decoration:none; display:inline-flex; align-items:center; gap:6px; margin-top:2px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
              support@winexcoin.com
            </a>
          </div>
        </div>
      </div>

      <div>
        <div class="footer-col-title">Protocol &amp; Specs</div>
        <ul class="footer-nav">
          <li><a href="https://github.com/WinexCoin/winex-core" target="_blank" rel="noopener" style="color:var(--accent-cyan); display:inline-flex; align-items:center; gap:6px;"><svg style="width:13px; height:13px;" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>GitHub Source Repo</a></li>
          <li><a href="https://discord.gg/pq3HV4jS" target="_blank" rel="noopener" style="color:#5865F2; display:inline-flex; align-items:center; gap:6px;"><svg style="width:13px; height:13px;" viewBox="0 0 127.14 96.36" fill="currentColor"><path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.86,53,48.83,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z"/></svg>Official Discord Community</a></li>
          <li><a href="/">Protocol Overview</a></li>
          <li><a href="/architecture">System Architecture</a></li>
          <li><a href="/tokenomics">Emission &amp; Halving</a></li>
          <li><a href="/whitepaper">Technical Whitepaper</a></li>
          <li><a href="/roadmap">Engineering Roadmap</a></li>
        </ul>
      </div>

      <div>
        <div class="footer-col-title">Network &amp; Clients</div>
        <ul class="footer-nav">
          <li><a href="https://github.com/WinexCoin/winex-core/releases" target="_blank" rel="noopener" style="color:var(--accent-primary); font-weight:600;">GitHub Releases (Binaries)</a></li>
          <li><a href="https://blockspot.io/coin/winex-wnx/" target="_blank" rel="noopener" style="color:#5fa8e0; font-weight:600; display:inline-flex; align-items:center; gap:6px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Blockspot.io (Verified)</a></li>
          <li><a href="/download">Desktop Download</a></li>
          <li><a href="/explorer">Live Block Explorer</a></li>
          <li><a href="/telemetry">Node RPC Telemetry</a></li>
          <li><a href="/whitepaper/download">Download Spec (.md)</a></li>
        </ul>
      </div>

      <div>
        <div class="footer-col-title">Legal &amp; Support</div>
        <ul class="footer-nav">
          <li><a href="/legal">Regulatory &amp; Legal Disclosures</a></li>
          <li><a href="/contact">Contact &amp; Support Desk</a></li>
          <li><a href="/terms">Terms &amp; MIT License</a></li>
          <li><a href="/privacy">Zero-KYC &amp; Privacy Policy</a></li>
          <li><a href="mailto:support@winexcoin.com" style="color:var(--accent-secondary);">support@winexcoin.com</a></li>
        </ul>
      </div>
    </div>

    <div class="footer-legal-ledger">
      <div>
        <strong>Regulatory &amp; Non-Financial Advice Notice (MiCA / SEC / SPK Compliance):</strong>
        WINEX (WNX) is an open-source, decentralized cryptographic Proof-of-Work protocol. No Initial Coin Offering (ICO), pre-sale, venture allocation, or investment contract exists. Nothing on this portal constitutes financial, investment, legal, or tax advice. No promises of value, liquidity, or capital yield are expressed or implied.
      </div>
      <div>
        <strong>Non-Custodial &amp; AS-IS Software Disclaimer:</strong>
        All software binaries and source distributions are provided &ldquo;AS IS&rdquo; under the MIT License without warranty of any kind. Cryptographic keys are generated exclusively on user hardware; protocol contributors cannot access, freeze, reverse, or recover private keys or on-chain transactions.
      </div>
    </div>

    <div class="footer-bottom">
      <span>&copy; 2026 WINEX (WNX) Core Protocol. Distributed under the MIT Open-Source License.</span>
      <span class="mono">SHA-256 PoW &bull; SECP256k1 &bull; Algorithmic Halving Model</span>
    </div>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/tsparticles@2.12.0/tsparticles.bundle.min.js"></script>
<script>
(function() {{
  if (window.tsParticles) {{
    window.tsParticles.load("tsparticles", {{
      fullScreen: {{ enable: false }},
      fpsLimit: 60,
      background: {{
        color: {{ value: "#06080d" }}
      }},
      interactivity: {{
        detectsOn: "window",
        events: {{
          onHover: {{
            enable: true,
            mode: "grab"
          }},
          onClick: {{
            enable: true,
            mode: "push"
          }},
          resize: true
        }},
        modes: {{
          grab: {{
            distance: 185,
            links: {{
              opacity: 0.65,
              color: "#38bdf8"
            }}
          }},
          push: {{
            quantity: 3
          }}
        }}
      }},
      particles: {{
        color: {{
          value: ["#38bdf8", "#10b981", "#94a3b8"]
        }},
        links: {{
          color: "#38bdf8",
          distance: 145,
          enable: true,
          opacity: 0.22,
          width: 1
        }},
        move: {{
          direction: "none",
          enable: true,
          outModes: {{ default: "bounce" }},
          random: false,
          speed: 0.9,
          straight: false
        }},
        number: {{
          density: {{
            enable: true,
            area: 900
          }},
          value: 75
        }},
        opacity: {{
          value: 0.48
        }},
        shape: {{
          type: "circle"
        }},
        size: {{
          value: {{ min: 1.2, max: 3.0 }}
        }}
      }},
      detectRetina: true
    }});
  }}
}})();
</script>
</body>
</html>
"""

# ==================== 1. OVERVIEW PAGE (/) ====================

@app.get("/", response_class=HTMLResponse)
def index_page():
    content = """
<style>
  .hero-split {
    display: grid;
    grid-template-columns: 1.08fr 1fr;
    gap: 44px;
    padding: 60px 0 56px;
    border-bottom: 1px solid var(--border-line);
    align-items: center;
  }
  @media (max-width: 960px) {
    .hero-split {
      grid-template-columns: 1fr;
      gap: 36px;
      padding: 44px 0;
    }
  }
  .hero-headline {
    font-size: clamp(2.25rem, 3.8vw, 3.25rem);
    margin-bottom: 22px;
  }
  .hero-lead {
    font-size: 17px;
    color: var(--text-body);
    line-height: 1.68;
    max-width: 62ch;
    margin-bottom: 32px;
  }
  .hero-invariants {
    margin-top: 36px;
    padding-top: 24px;
    border-top: 1px solid var(--border-line);
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
  }
  @media (max-width: 560px) {
    .hero-invariants { grid-template-columns: 1fr; }
  }
  .inv-val {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    font-size: 18px;
    font-weight: 700;
    color: var(--text-main);
  }
  .inv-lbl {
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 4px;
  }

  /* Bare Floating 3D Coin directly over Background Mesh */
  .coin-bare-wrap {
    position: relative;
    width: 100%;
    height: 440px;
    background: transparent;
    border: none;
    cursor: grab;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .coin-bare-wrap:active {
    cursor: grabbing;
  }
  #coinCanvas {
    width: 100%;
    height: 100%;
    display: block;
    background: transparent;
  }

  /* Live Consensus Strip + Block Feed below Hero */
  .live-ledger-section {
    padding: 48px 0;
    border-bottom: 1px solid var(--border-line);
  }
  .live-ledger-hdr {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 12px;
  }
  .term-status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--accent-primary);
    font-weight: 600;
  }
  .term-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent-primary);
    display: inline-block;
  }

  .section-hdr {
    padding: 56px 0 28px;
  }
  .section-hdr h2 {
    font-size: clamp(1.5rem, 2.4vw, 2rem);
    margin-bottom: 10px;
  }
  .section-hdr p {
    font-size: 16px;
    color: var(--text-muted);
    max-width: 64ch;
  }

  .inline-link {
    display: inline-block;
    margin-top: 14px;
    color: var(--accent-secondary);
    font-size: 14px;
    font-weight: 600;
    text-decoration: none;
  }
  .inline-link:hover {
    text-decoration: underline;
  }
</style>

<script type="importmap">
{
  "imports": {
    "three": "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js",
    "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"
  }
}
</script>

<section class="hero-split">
  <div>
    <h1 class="hero-headline">Sovereign Proof-of-Work Electronic Cash.</h1>
    <p class="hero-lead">
      WINEX (WNX) is an autonomous, non-custodial Layer-1 cryptocurrency protocol operating on deterministic double SHA-256 Proof-of-Work. Engineered without venture capital lockups or administrative master keys, it enforces a strictly capped finite issuance with algorithmic block reward halvings every 125,000 blocks.
    </p>
    <div class="btn-row">
      <a href="/download" class="btn-primary">Download Suite</a>
      <a href="https://github.com/WinexCoin/winex-core" target="_blank" rel="noopener" class="btn-secondary" style="display:inline-flex; align-items:center; gap:8px;">
        <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        GitHub Source
      </a>
      <a href="/explorer" class="btn-secondary">Inspect Block Explorer</a>
    </div>

    <div class="hero-invariants">
      <div>
        <div class="inv-val" style="color:var(--accent-primary);">Deflationary</div>
        <div class="inv-lbl">Hard Cap Issuance</div>
      </div>
      <div>
        <div class="inv-val">40.0000 WNX</div>
        <div class="inv-lbl">Initial Block Subsidy</div>
      </div>
      <div>
        <div class="inv-val">125,000 Blocks</div>
        <div class="inv-lbl">Halving Cadence</div>
      </div>
    </div>
  </div>

  <!-- Bare 3D WINEX Coin Floating Over Background -->
  <div class="coin-bare-wrap" id="coinViewport" aria-label="3D WINEX Coin">
    <canvas id="coinCanvas"></canvas>
  </div>
</section>

<!-- Live Layer-1 Consensus Telemetry Strip -->
<section class="live-ledger-section" aria-label="Live Mainnet Consensus State">
  <div class="live-ledger-hdr">
    <h2 style="font-size:20px;">Live Mainnet Consensus State</h2>
    <span class="term-status"><span class="term-dot"></span>NODE SYNCED &bull; 15m TARGET CADENCE</span>
  </div>
  <div class="ledger-strip" style="margin-bottom:0;">
    <div class="ledger-cell">
      <div class="ledger-label">Current Block Height</div>
      <div id="homeHeight" class="ledger-value">#...</div>
      <div class="ledger-note">Double SHA-256 PoW</div>
    </div>
    <div class="ledger-cell">
      <div class="ledger-label">Active Block Subsidy</div>
      <div id="homeReward" class="ledger-value" style="color:var(--accent-primary);">40.0000 WNX</div>
      <div class="ledger-note">Halves every 125,000 blocks</div>
    </div>
    <div class="ledger-cell">
      <div class="ledger-label">Remaining Mineable Pool</div>
      <div id="homePool" class="ledger-value" style="color:var(--accent-secondary);">9,998,240 WNX</div>
      <div id="homePoolSub" class="ledger-note">Ready to be mined via PoW</div>
    </div>
    <div class="ledger-cell">
      <div class="ledger-label">Active Mesh Peers</div>
      <div id="homePeers" class="ledger-value" style="color:var(--accent-secondary);">... Nodes</div>
      <div class="ledger-note">Autonomous P2P Gossip</div>
    </div>
  </div>
</section>

<section class="section-hdr">
  <h2>Protocol Architecture &amp; Engineering Guarantees</h2>
  <p>Built from first principles as a self-contained cryptographic ledger without external corporate dependencies.</p>
</section>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h3 class="editorial-title">Burned Keys &amp; Immutable Issuance</h3>
    </div>
    <div class="editorial-body">
      <p>
        WINEX eliminates administrative privileges, emergency pause switches, and contract upgrade proxies. Every single WNX unit enters circulation exclusively through competitive double SHA-256 Proof-of-Work block discovery.
      </p>
      <p>
        Autonomous difficulty retargeting calibrates the cryptographic target to maintain a 900-second (15-minute) average block interval regardless of global hashrate fluctuations, locking each 125,000-block halving epoch to its mathematical schedule.
      </p>
      <a href="/tokenomics" class="inline-link">Examine the Algorithmic Emission Schedule &rarr;</a>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h3 class="editorial-title">Embedded Background Full Node</h3>
    </div>
    <div class="editorial-body">
      <p>
        Every desktop client distribution embeds the standalone Layer-1 node daemon (<code>WINEX_Node</code>). Launching either the graphical wallet or the high-speed miner automatically initializes the local consensus validator on <code>127.0.0.1:8081</code> in the background.
      </p>
      <p>
        This architectural decision guarantees that every active wallet holder or miner simultaneously relays blocks, validates ECDSA signatures, and strengthens the peer-to-peer mesh without manual server configuration.
      </p>
      <a href="/architecture" class="inline-link">Review P2P Mesh &amp; Node Specifications &rarr;</a>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h3 class="editorial-title">Client-Side SECP256k1 &amp; Zero-KYC Privacy</h3>
    </div>
    <div class="editorial-body">
      <p>
        Private keys and BIP-39 mnemonic seeds are generated locally using hardware CSPRNG entropy and stored in AES-256-GCM encrypted keystores. No account registration, identity verification, or behavioral telemetry exists at any layer of the stack.
      </p>
      <a href="/privacy" class="inline-link">Read Data Sovereignty &amp; Privacy Architecture &rarr;</a>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h3 class="editorial-title">Native Cross-Platform Toolchains</h3>
    </div>
    <div class="editorial-body">
      <p>
        Compiled into dependency-free native machine code across Windows x86_64 (<code>.exe</code> suite with native GUI launcher), Linux x86_64 (universal <code>.AppImage</code> and static ELF binaries), and macOS universal bundles (Apple Silicon ARM64 &amp; Intel <code>.app</code>).
      </p>
      <a href="/download" class="inline-link">View Platform Release Specifications &rarr;</a>
    </div>
  </div>

  <div class="editorial-row" style="border-top: 1px solid var(--border-line); padding-top: 36px; margin-top: 16px;">
    <div>
      <h3 class="editorial-title" style="color: var(--accent-secondary);">Compliance, Legal &amp; Support</h3>
    </div>
    <div class="editorial-body">
      <p>
        WINEX Core operates as an independent, non-custodial open-source Layer-1 Proof-of-Work software protocol (MIT License). Zero public or private sale of tokens has ever occurred. Zero funds, fiat deposits, or pooled investments are accepted.
      </p>
      <p>
        Maintainers will never send unsolicited direct messages or ask for private keys. For official inquiries, incident disclosures, or institutional verification, access our legal and support desks:
      </p>
      <div style="display:flex; flex-wrap:wrap; gap:14px; margin-top:16px;">
        <a href="/legal" class="btn btn-secondary" style="font-size:13.5px;">⚖️ Regulatory &amp; Legal Disclosures</a>
        <a href="/contact" class="btn btn-secondary" style="font-size:13.5px;">✉️ Contact &amp; Support Desk (support@winexcoin.com)</a>
      </div>
    </div>
  </div>
</div>

<script type="module">
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

const canvas = document.getElementById('coinCanvas');
const viewport = document.getElementById('coinViewport');

if (canvas && viewport) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setClearColor(0x000000, 0);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(viewport.clientWidth, viewport.clientHeight);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;

  const scene = new THREE.Scene();

  // Matches render_turntable.py: 100mm telephoto perspective, full coin framed with clean margin
  const camera = new THREE.PerspectiveCamera(26, viewport.clientWidth / viewport.clientHeight, 0.1, 100);
  camera.position.set(0, 0.35, 5.0);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.05;
  controls.enablePan = false;
  controls.enableZoom = false;
  controls.target.set(0, 0, 0);

  // Balanced Studio Lighting for 3D Spinning Coin (Clear body contours, rings, reeded edge & crisp silver W)
  const hemiLight = new THREE.HemisphereLight(0xf1f5f9, 0x0f172a, 0.75);
  scene.add(hemiLight);

  const frontKey = new THREE.DirectionalLight(0xffffff, 2.5);
  frontKey.position.set(-2.6, 3.2, 4.4);
  scene.add(frontKey);

  const frontFill = new THREE.DirectionalLight(0xd9ebff, 1.4);
  frontFill.position.set(3.2, -1.5, 4.0);
  scene.add(frontFill);

  const backKey = new THREE.DirectionalLight(0xffffff, 2.5);
  backKey.position.set(2.6, 3.2, -4.4);
  scene.add(backKey);

  const backFill = new THREE.DirectionalLight(0xd9ebff, 1.4);
  backFill.position.set(-3.2, -1.5, -4.0);
  scene.add(backFill);

  const topRim = new THREE.DirectionalLight(0xffffff, 2.2);
  topRim.position.set(0.0, 4.2, 1.2);
  scene.add(topRim);

  // Fixed 6-degree tilt group + continuous 360deg turntable spin group
  const tiltGroup = new THREE.Group();
  tiltGroup.rotation.x = THREE.MathUtils.degToRad(-6);
  scene.add(tiltGroup);

  const spinGroup = new THREE.Group();
  tiltGroup.add(spinGroup);

  const loader = new GLTFLoader();
  loader.load('/assets/w_coin.glb?v=4', (gltf) => {
    const coinModel = gltf.scene;
    coinModel.traverse((child) => {
      if (child.isMesh && child.material) {
        child.material.normalMap = null;
        if (child.material.name && child.material.name.includes('Silver')) {
          // Brushed satin-silver W monogram
          child.material.color = new THREE.Color(0xdce2ec);
          child.material.metalness = 0.28;
          child.material.roughness = 0.32;
        } else {
          // Dark titanium/obsidian coin body with clear ring & reed visibility
          child.material.color = new THREE.Color(0x14171f);
          child.material.metalness = 0.12;
          child.material.roughness = 0.36;
        }
        child.material.needsUpdate = true;
      }
    });
    spinGroup.add(coinModel);
  });

  window.addEventListener('resize', () => {
    if (!viewport) return;
    camera.aspect = viewport.clientWidth / viewport.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(viewport.clientWidth, viewport.clientHeight);
  });

  const clock = new THREE.Clock();
  function animate() {
    requestAnimationFrame(animate);
    const delta = clock.getDelta();
    // Exact 6-second 360-degree turntable spin matching render_turntable.py
    spinGroup.rotation.y += delta * ((Math.PI * 2) / 6.0);
    controls.update();
    renderer.render(scene, camera);
  }
  animate();
}
</script>

<script>
async function refreshHomeLedger() {
  try {
    const sRes = await fetch('/api/status?t=' + Date.now(), { cache: 'no-store' });
    const s = await sRes.json();
    if (document.getElementById('homeHeight')) document.getElementById('homeHeight').innerText = '#' + (s.block_height != null ? s.block_height : 1);
    if (document.getElementById('homeReward')) document.getElementById('homeReward').innerText = (s.block_reward != null ? s.block_reward.toFixed(4) : '40.0000') + ' WNX';
    if (document.getElementById('homePool')) document.getElementById('homePool').innerText = (s.pool_remaining != null ? s.pool_remaining.toLocaleString() : '9,998,240') + ' WNX';
    if (document.getElementById('homePoolSub')) document.getElementById('homePoolSub').innerText = 'Ready to be mined via PoW';
    if (document.getElementById('homePeers')) document.getElementById('homePeers').innerText = (s.peer_count != null ? s.peer_count : 1) + ' Active';
  } catch (e) {}
}
refreshHomeLedger();
setInterval(refreshHomeLedger, 2000);
</script>
"""
    return render_layout("Overview", "overview", content)

# ==================== 2. DOWNLOAD PAGE (/download) ====================

@app.get("/download", response_class=HTMLResponse)
@app.get("/downloads", response_class=HTMLResponse)
def download_page(request: Request):
    pro_content = """
<style>
.dl-hero {
  text-align: center;
  padding: 36px 0 24px;
}
.dl-hero h1 {
  font-size: 38px;
  font-weight: 800;
  letter-spacing: -0.03em;
  margin-bottom: 8px;
}
.dl-hero p {
  color: var(--text-muted);
  font-size: 15px;
}
.os-pill-row {
  display: flex;
  justify-content: center;
  gap: 10px;
  margin: 28px 0 36px;
  flex-wrap: wrap;
}
.os-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 18px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 9999px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s ease;
  user-select: none;
}
.os-pill:hover {
  color: var(--text-main);
  border-color: var(--border-hover);
  background: var(--surface-card);
}
.os-pill.active {
  background: #ffffff;
  color: #000000;
  border-color: #ffffff;
}
.os-pill svg {
  width: 15px;
  height: 15px;
  fill: currentColor;
}
.dl-panel {
  display: none;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 32px;
  margin-bottom: 24px;
}
.dl-panel.active {
  display: block;
}
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 12px;
}
.panel-title {
  font-size: 20px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 10px;
}
.badge-ver {
  font-size: 11px;
  padding: 2px 8px;
  background: rgba(56, 189, 248, 0.1);
  color: #38bdf8;
  border: 1px solid rgba(56, 189, 248, 0.25);
  border-radius: 4px;
  font-family: var(--font-mono);
}
.terminal-window {
  background: #090b10;
  border: 1px solid #1f293d;
  border-radius: 10px;
  margin-top: 18px;
  box-shadow: 0 12px 36px rgba(0, 0, 0, 0.45);
  overflow: hidden;
}
.terminal-topbar {
  background: #0f131c;
  border-bottom: 1px solid #1f293d;
  padding: 10px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.terminal-dots {
  display: flex;
  align-items: center;
  gap: 7px;
}
.term-dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  display: inline-block;
}
.term-dot.red { background: #ff5f56; }
.term-dot.yellow { background: #ffbd2e; }
.term-dot.green { background: #27c93f; }
.terminal-title {
  font-family: var(--font-mono);
  font-size: 12px;
  color: #64748b;
  font-weight: 500;
  letter-spacing: 0.02em;
}
.cli-box {
  background: transparent;
  padding: 16px 20px;
  font-family: var(--font-mono);
  font-size: 13.5px;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.cli-cmd-wrap {
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: all;
  word-break: break-all;
}
.cli-prompt {
  color: #10b981;
  font-weight: 700;
  user-select: none;
}
.copy-btn {
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.16);
  color: #f8fafc;
  padding: 7px 16px;
  border-radius: 6px;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all 0.15s ease;
}
.copy-btn:hover {
  background: #ffffff;
  color: #000000;
  border-color: #ffffff;
}
.suite-btn-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 20px;
}
.suite-btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: #ffffff;
  color: #000000;
  padding: 10px 22px;
  border-radius: 6px;
  font-size: 13.5px;
  font-weight: 700;
  text-decoration: none;
  transition: opacity 0.15s;
}
.suite-btn-primary:hover {
  opacity: 0.9;
}

/* Quick Setup Guide Cards */
.setup-guide-wrap {
  margin-top: 28px;
  padding-top: 22px;
  border-top: 1px solid var(--border-line);
}
.setup-guide-title {
  font-size: 14.5px;
  font-weight: 700;
  color: var(--text-main);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.setup-steps-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px;
}
@media (max-width: 768px) {
  .setup-steps-grid { grid-template-columns: 1fr; }
}
.setup-step-card {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid var(--border-line);
  border-radius: 8px;
  padding: 16px;
  transition: border-color 0.15s ease;
}
.setup-step-card:hover {
  border-color: var(--border-strong);
}
.step-num {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  background: rgba(16, 185, 129, 0.12);
  color: #10b981;
  border: 1px solid rgba(16, 185, 129, 0.25);
  border-radius: 50%;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  margin-bottom: 10px;
}
.step-heading {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--text-main);
  margin-bottom: 6px;
}
.step-desc {
  font-size: 12.5px;
  color: var(--text-muted);
  line-height: 1.55;
}
.step-desc code {
  background: rgba(255, 255, 255, 0.06);
  padding: 2px 5px;
  border-radius: 3px;
  font-size: 11.5px;
  color: #38bdf8;
}

.suite-info-list {
  margin-top: 18px;
  padding-left: 18px;
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.7;
}
</style>

<div class="dl-hero">
  <h1>Download WINEX Core</h1>
  <p>Self-contained sovereign cryptocurrency suite for Windows, Linux, and macOS.</p>
</div>

<div class="os-pill-row">
  <div class="os-pill active" onclick="switchOsTab('linux')">
    <svg viewBox="0 0 24 25" style="width:18px; height:18px;" fill="currentColor" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M10.06 5.86a.2.2 0 0 0-.16.11q-.06.1-.1.1-.05.01-.05-.05 0-.13.2-.16zm.92.15q-.05 0-.12-.07a.2.2 0 0 0-.19-.05q.26-.12.34.02l.02.04q0 .04-.05.06m-3.72 4.52h-.01a.1.1 0 0 0-.05.04l-.05.12-.06.16-.1.13q-.12.12-.02.13.05 0 .14-.08.08-.07.13-.18l.02-.08.02-.07.02-.04v-.08l-.01-.02zm9.06 3.81q0-.19-.58-.44l.13-.56.04-.24v-.24l-.01-.2q0-.13-.04-.25v.01l-.1-.48-.05-.28q-.16-.62-.5-1.1v.01q-.3-.48-.75-.79h-.01q.36.36.6.86v.01a4 4 0 0 1 .57 2.98v-.03a.54.54 0 0 1-.53.44q-.34.05-.4-.2a3 3 0 0 1-.1-.88v-.02q0-.6-.12-1.15v.04q-.09-.44-.22-.78l.02.05a3 3 0 0 0-.22-.5l.01.01-.3-.42-.08-.07q-.13-.62-.34-1.14l.02.05a3 3 0 0 0-.32-.6l-.24-.33v-.02a1.1 1.1 0 0 1-.1-1v.01a1 1 0 0 0 .04-.53q-.05-.17-.47-.26a2 2 0 0 1-.48-.2l.01.01q-.16-.1-.36-.16h-.01q-.09-.01-.12-.28v-.11q0-.24.09-.44.1-.25.37-.28h.08c.21 0 .4.13.46.31a.8.8 0 0 1 .05.63q-.12.2-.02.27.1.09.31 0 .14-.03.14-.37v-.4q-.04-.3-.15-.54v.01a1 1 0 0 0-.21-.32 1 1 0 0 0-.25-.16l-.28-.08h-.01q-1.14.09-.94 1.42l-.02.16a.5.5 0 0 0-.3-.11 2 2 0 0 0-.37 0h.01q-.13.03-.16-.05v-.13q0-.45-.18-.84v.02a.6.6 0 0 0-.47-.36h-.01q-.31.02-.43.28-.15.29-.17.64v.05q0 .18.04.35.03.21.14.4V6q.07.17.16.14a.3.3 0 0 0 .16-.14q.04-.1-.07-.09-.07 0-.16-.15a1 1 0 0 1-.1-.36v-.05q0-.2.1-.34a.4.4 0 0 1 .36-.15q.2.03.28.22.1.2.1.42 0 .13-.02.24-.2.11-.32.3a1 1 0 0 1-.3.24l-.21.14a1 1 0 0 0-.17.28v.05q0 .1.08.14.16.09.27.21l.16.2q.09.1.2.14.17.06.38.07h.08q.54 0 1.02-.17h-.02l.24-.07.37-.1.32-.15q.13-.06.22-.18.1-.15.2-.08.06.03.08.08v.03q0 .07-.03.1a.3.3 0 0 1-.18.1q-.37.12-.64.25l.04-.02-.48.2q-.32.16-.72.25h-.02a3 3 0 0 1-.86-.02h.02q-.11-.01-.1.02.07.12.18.2a1 1 0 0 0 .71.24q.2-.02.4-.08h-.02q.22-.07.4-.15h-.02a5 5 0 0 0 .67-.36l.25-.12h.01a.3.3 0 0 1 .19-.03q.08.03.09.11l-.01.05-.04.05-.07.05-.29.16-.1.04q-.4.22-.73.48l.01-.01q-.3.24-.68.44l-.02.01a.5.5 0 0 1-.52.01q-.41-.3-.66-.76-.24-.34-.27-.24l-.01.09v.02q-.02.33-.16.6-.15.33-.31.58-.16.28-.22.6v.02a1 1 0 0 0 .12.67q-.25.06-.67.95-.34.66-.5 1.46v.03a8 8 0 0 0-.01.9q0 .26-.07.47-.08.24-.3.02-.37-.4-.38-.98v-.01a2 2 0 0 1 .04-.61v.01q.04-.2-.01-.19l-.04.06a1.9 1.9 0 0 0 .1 1.77v-.01q.1.18.26.3.22.16.26.2.51.51 1.07.95l.03.02q.9.7.99.8.17.16.18.4v.04c0 .36-.28.65-.63.67q.15.26.31.48v-.01q.18.25.29.55v.02a3 3 0 0 1 .08.75q.48-.26.07-.98l-.11-.17-.12-.19a.3.3 0 0 1 .13-.1l.1-.02q.06 0 .12.05.48.55 1.76.38c.76 0 1.44-.36 1.87-.92q.25-.4.37-.32.13.06.1.55-.07.54-.25 1v-.03a1 1 0 0 0-.06.4q.04.15.26.17l.15-.82q.1-.42.14-.92v-.11q0-.38-.07-.73v.03a6 6 0 0 1-.07-1.04v-.03q0-.41.24-.71a.7.7 0 0 1 .54-.19v-.01a.6.6 0 0 1 .36-.55 1.3 1.3 0 0 1 .78-.11q.36.03.65.24M9.67 5.57a.6.6 0 0 0-.03-.32q-.06-.13-.12-.15-.1-.03-.1.07.01.04.06.07.11 0 .07.15-.04.22.09.22.03 0 .03-.03m4.44 2.1q-.02-.09-.07-.13l-.14-.05-.15-.06-.1-.09-.08-.08-.06-.07-.04-.04-.04.01q-.15.17.07.47.15.23.41.33h.02q.1 0 .14-.09a.3.3 0 0 0 .04-.21M12.22 5.4a.4.4 0 0 0-.17-.34q-.06-.04-.1-.04t-.08.03v.04l.05.03q.15.04.2.33 0 .03.08-.02zm.57-2.47-.02-.06-.1-.07-.35-.22q-.08 0-.12.08a.2.2 0 0 0-.01.14v.13l-.07.11-.06.1q-.01.01.03.09l.04.01.04-.01.12-.1.16-.1h.1l.16-.03a.1.1 0 0 0 .09-.07m6 14.21q.18.1.32.26.1.1.13.25v.06l-.03.19q-.05.14-.16.23l-.24.2h-.01l-.3.2h-.02a12 12 0 0 1-.96.48q-.5.27-.92.6l.02-.01q-.44.34-.81.68-.29.2-.67.2h-.05a2 2 0 0 1-.95-.15h.01a1 1 0 0 1-.31-.25l-.17-.26a.5.5 0 0 0-.24-.21 1 1 0 0 0-.49-.1h-1.99l-.62.03q-.46 0-.85.16h.01q-.32.1-.57.32-.2.17-.45.29-.24.13-.53.13h-.05a5 5 0 0 1-1.2-.34l.03.01c-.42-.17-.94-.32-1.47-.44l-.08-.02a14 14 0 0 0-1.07-.2l-.42-.1a1 1 0 0 1-.36-.15 1 1 0 0 1-.17-.2 1 1 0 0 1 .07-.71q.12-.25.19-.55v-.08q0-.2-.04-.38v.01l-.1-.45q-.05-.16-.05-.35v-.05q0-.16.1-.27a1 1 0 0 1 .62-.15h.02q.33 0 .62-.13h-.01q.26-.15.44-.37a1 1 0 0 0 .13-.54q.08.15.08.37a.9.9 0 0 1-.41.75 1.4 1.4 0 0 1-.9.16h.01q-.36-.03-.45.1-.15.16.05.61l.1.2H3.6l.09.18.04.18.02.24q-.05.28-.19.52a1 1 0 0 0-.14.5q.03.18.39.28l.9.2 1.05.2.78.24q.54.17.88.25a2 2 0 0 0 .6.04h-.01q.4-.04.68-.3.21-.2.25-.5v-.07q0-.3-.09-.57v.01q-.08-.31-.2-.56v.01l-.2-.38a23 23 0 0 0-1.83-2.6l.03.04q-.72-.8-1.2-.43-.11.1-.16-.16a2 2 0 0 1-.02-.4q.01-.3.11-.56.12-.27.26-.5v.01q.12-.2.22-.43v-.01l.6-1.6q.15-.37.33-.67l-.01.03q.17-.32.41-.57.79-.9 1.3-2.02l.01-.05a41 41 0 0 1-.17-3.49q0-.76.27-1.42l-.01.02q.38-.75 1.11-1.1l.01-.01a2.3 2.3 0 0 1 1.11-.22h.07q.56 0 1.08.15l-.03-.01q.54.15.95.44.64.5.96 1.27v.02a3 3 0 0 1 .32 1.57v-.01.2q0 1.11.33 2.12l-.02-.05q.46 1.36 1.41 2.31.66.75 1.04 1.69l.02.04q.4.89.62 1.97l.01.05a4 4 0 0 1 .05.91v-.01q0 .31-.13.6v-.01q-.1.21-.2.23a.5.5 0 0 0-.25.2l-.3.38q-.16.21-.41.35h-.01a1.2 1.2 0 0 1-.65.15l-.34-.05h.01a1 1 0 0 1-.24-.15l-.14-.16-.12-.2v-.02l-.1-.2q-.23-.4-.43-.32-.21.07-.3.52a2 2 0 0 0 .08 1.04v-.01a5 5 0 0 1 0 2.1v-.03q-.04.14-.04.31 0 .43.24.75a.9.9 0 0 0 .77.35q.53-.05.9-.38.42-.37.92-.68l.03-.02q.47-.25 1.05-.44l.04-.01q.48-.15.83-.4v.01q.25-.2.19-.36a.6.6 0 0 0-.26-.3q-.25-.16-.54-.25h-.01a.9.9 0 0 1-.53-.5v-.01q-.16-.32-.16-.72v-.11a.7.7 0 0 1 .17-.45q0 .33.08.62v-.02q.07.24.16.45v-.02q.08.18.21.3.1.12.22.2z"></path></svg>
    Linux
  </div>
  <div class="os-pill" onclick="switchOsTab('windows')">
    <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M2 3.5L10.5 2.3V11.2H2V3.5M2 12.8H10.5V21.7L2 20.5V12.8M11.8 2.1L22 0.7V11.2H11.8V2.1M11.8 12.8H22V23.3L11.8 21.9V12.8Z"/></svg>
    Windows
  </div>
  <div class="os-pill" onclick="switchOsTab('macos')">
    <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.61 1.34-.55.63-.99 1.66-.86 2.69.98.08 2.01-.52 2.55-1.18z"/></svg>
    macOS
  </div>
</div>

<!-- Linux Panel (Terminal-First & Suite Package) -->
<div id="panel-linux" class="dl-panel active">
  <div class="panel-header">
    <div class="panel-title">
      <svg viewBox="0 0 24 25" style="width:18px; height:18px;" fill="currentColor" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M10.06 5.86a.2.2 0 0 0-.16.11q-.06.1-.1.1-.05.01-.05-.05 0-.13.2-.16zm.92.15q-.05 0-.12-.07a.2.2 0 0 0-.19-.05q.26-.12.34.02l.02.04q0 .04-.05.06m-3.72 4.52h-.01a.1.1 0 0 0-.05.04l-.05.12-.06.16-.1.13q-.12.12-.02.13.05 0 .14-.08.08-.07.13-.18l.02-.08.02-.07.02-.04v-.08l-.01-.02zm9.06 3.81q0-.19-.58-.44l.13-.56.04-.24v-.24l-.01-.2q0-.13-.04-.25v.01l-.1-.48-.05-.28q-.16-.62-.5-1.1v.01q-.3-.48-.75-.79h-.01q.36.36.6.86v.01a4 4 0 0 1 .57 2.98v-.03a.54.54 0 0 1-.53.44q-.34.05-.4-.2a3 3 0 0 1-.1-.88v-.02q0-.6-.12-1.15v.04q-.09-.44-.22-.78l.02.05a3 3 0 0 0-.22-.5l.01.01-.3-.42-.08-.07q-.13-.62-.34-1.14l.02.05a3 3 0 0 0-.32-.6l-.24-.33v-.02a1.1 1.1 0 0 1-.1-1v.01a1 1 0 0 0 .04-.53q-.05-.17-.47-.26a2 2 0 0 1-.48-.2l.01.01q-.16-.1-.36-.16h-.01q-.09-.01-.12-.28v-.11q0-.24.09-.44.1-.25.37-.28h.08c.21 0 .4.13.46.31a.8.8 0 0 1 .05.63q-.12.2-.02.27.1.09.31 0 .14-.03.14-.37v-.4q-.04-.3-.15-.54v.01a1 1 0 0 0-.21-.32 1 1 0 0 0-.25-.16l-.28-.08h-.01q-1.14.09-.94 1.42l-.02.16a.5.5 0 0 0-.3-.11 2 2 0 0 0-.37 0h.01q-.13.03-.16-.05v-.13q0-.45-.18-.84v.02a.6.6 0 0 0-.47-.36h-.01q-.31.02-.43.28-.15.29-.17.64v.05q0 .18.04.35.03.21.14.4V6q.07.17.16.14a.3.3 0 0 0 .16-.14q.04-.1-.07-.09-.07 0-.16-.15a1 1 0 0 1-.1-.36v-.05q0-.2.1-.34a.4.4 0 0 1 .36-.15q.2.03.28.22.1.2.1.42 0 .13-.02.24-.2.11-.32.3a1 1 0 0 1-.3.24l-.21.14a1 1 0 0 0-.17.28v.05q0 .1.08.14.16.09.27.21l.16.2q.09.1.2.14.17.06.38.07h.08q.54 0 1.02-.17h-.02l.24-.07.37-.1.32-.15q.13-.06.22-.18.1-.15.2-.08.06.03.08.08v.03q0 .07-.03.1a.3.3 0 0 1-.18.1q-.37.12-.64.25l.04-.02-.48.2q-.32.16-.72.25h-.02a3 3 0 0 1-.86-.02h.02q-.11-.01-.1.02.07.12.18.2a1 1 0 0 0 .71.24q.2-.02.4-.08h-.02q.22-.07.4-.15h-.02a5 5 0 0 0 .67-.36l.25-.12h.01a.3.3 0 0 1 .19-.03q.08.03.09.11l-.01.05-.04.05-.07.05-.29.16-.1.04q-.4.22-.73.48l.01-.01q-.3.24-.68.44l-.02.01a.5.5 0 0 1-.52.01q-.41-.3-.66-.76-.24-.34-.27-.24l-.01.09v.02q-.02.33-.16.6-.15.33-.31.58-.16.28-.22.6v.02a1 1 0 0 0 .12.67q-.25.06-.67.95-.34.66-.5 1.46v.03a8 8 0 0 0-.01.9q0 .26-.07.47-.08.24-.3.02-.37-.4-.38-.98v-.01a2 2 0 0 1 .04-.61v.01q.04-.2-.01-.19l-.04.06a1.9 1.9 0 0 0 .1 1.77v-.01q.1.18.26.3.22.16.26.2.51.51 1.07.95l.03.02q.9.7.99.8.17.16.18.4v.04c0 .36-.28.65-.63.67q.15.26.31.48v-.01q.18.25.29.55v.02a3 3 0 0 1 .08.75q.48-.26.07-.98l-.11-.17-.12-.19a.3.3 0 0 1 .13-.1l.1-.02q.06 0 .12.05.48.55 1.76.38c.76 0 1.44-.36 1.87-.92q.25-.4.37-.32.13.06.1.55-.07.54-.25 1v-.03a1 1 0 0 0-.06.4q.04.15.26.17l.15-.82q.1-.42.14-.92v-.11q0-.38-.07-.73v.03a6 6 0 0 1-.07-1.04v-.03q0-.41.24-.71a.7.7 0 0 1 .54-.19v-.01a.6.6 0 0 1 .36-.55 1.3 1.3 0 0 1 .78-.11q.36.03.65.24M9.67 5.57a.6.6 0 0 0-.03-.32q-.06-.13-.12-.15-.1-.03-.1.07.01.04.06.07.11 0 .07.15-.04.22.09.22.03 0 .03-.03m4.44 2.1q-.02-.09-.07-.13l-.14-.05-.15-.06-.1-.09-.08-.08-.06-.07-.04-.04-.04.01q-.15.17.07.47.15.23.41.33h.02q.1 0 .14-.09a.3.3 0 0 0 .04-.21M12.22 5.4a.4.4 0 0 0-.17-.34q-.06-.04-.1-.04t-.08.03v.04l.05.03q.15.04.2.33 0 .03.08-.02zm.57-2.47-.02-.06-.1-.07-.35-.22q-.08 0-.12.08a.2.2 0 0 0-.01.14v.13l-.07.11-.06.1q-.01.01.03.09l.04.01.04-.01.12-.1.16-.1h.1l.16-.03a.1.1 0 0 0 .09-.07m6 14.21q.18.1.32.26.1.1.13.25v.06l-.03.19q-.05.14-.16.23l-.24.2h-.01l-.3.2h-.02a12 12 0 0 1-.96.48q-.5.27-.92.6l.02-.01q-.44.34-.81.68-.29.2-.67.2h-.05a2 2 0 0 1-.95-.15h.01a1 1 0 0 1-.31-.25l-.17-.26a.5.5 0 0 0-.24-.21 1 1 0 0 0-.49-.1h-1.99l-.62.03q-.46 0-.85.16h.01q-.32.1-.57.32-.2.17-.45.29-.24.13-.53.13h-.05a5 5 0 0 1-1.2-.34l.03.01c-.42-.17-.94-.32-1.47-.44l-.08-.02a14 14 0 0 0-1.07-.2l-.42-.1a1 1 0 0 1-.36-.15 1 1 0 0 1-.17-.2 1 1 0 0 1 .07-.71q.12-.25.19-.55v-.08q0-.2-.04-.38v.01l-.1-.45q-.05-.16-.05-.35v-.05q0-.16.1-.27a1 1 0 0 1 .62-.15h.02q.33 0 .62-.13h-.01q.26-.15.44-.37a1 1 0 0 0 .13-.54q.08.15.08.37a.9.9 0 0 1-.41.75 1.4 1.4 0 0 1-.9.16h.01q-.36-.03-.45.1-.15.16.05.61l.1.2H3.6l.09.18.04.18.02.24q-.05.28-.19.52a1 1 0 0 0-.14.5q.03.18.39.28l.9.2 1.05.2.78.24q.54.17.88.25a2 2 0 0 0 .6.04h-.01q.4-.04.68-.3.21-.2.25-.5v-.07q0-.3-.09-.57v.01q-.08-.31-.2-.56v.01l-.2-.38a23 23 0 0 0-1.83-2.6l.03.04q-.72-.8-1.2-.43-.11.1-.16-.16a2 2 0 0 1-.02-.4q.01-.3.11-.56.12-.27.26-.5v.01q.12-.2.22-.43v-.01l.6-1.6q.15-.37.33-.67l-.01.03q.17-.32.41-.57.79-.9 1.3-2.02l.01-.05a41 41 0 0 1-.17-3.49q0-.76.27-1.42l-.01.02q.38-.75 1.11-1.1l.01-.01a2.3 2.3 0 0 1 1.11-.22h.07q.56 0 1.08.15l-.03-.01q.54.15.95.44.64.5.96 1.27v.02a3 3 0 0 1 .32 1.57v-.01.2q0 1.11.33 2.12l-.02-.05q.46 1.36 1.41 2.31.66.75 1.04 1.69l.02.04q.4.89.62 1.97l.01.05a4 4 0 0 1 .05.91v-.01q0 .31-.13.6v-.01q-.1.21-.2.23a.5.5 0 0 0-.25.2l-.3.38q-.16.21-.41.35h-.01a1.2 1.2 0 0 1-.65.15l-.34-.05h.01a1 1 0 0 1-.24-.15l-.14-.16-.12-.2v-.02l-.1-.2q-.23-.4-.43-.32-.21.07-.3.52a2 2 0 0 0 .08 1.04v-.01a5 5 0 0 1 0 2.1v-.03q-.04.14-.04.31 0 .43.24.75a.9.9 0 0 0 .77.35q.53-.05.9-.38.42-.37.92-.68l.03-.02q.47-.25 1.05-.44l.04-.01q.48-.15.83-.4v.01q.25-.2.19-.36a.6.6 0 0 0-.26-.3q-.25-.16-.54-.25h-.01a.9.9 0 0 1-.53-.5v-.01q-.16-.32-.16-.72v-.11a.7.7 0 0 1 .17-.45q0 .33.08.62v-.02q.07.24.16.45v-.02q.08.18.21.3.1.12.22.2z"></path></svg>
      WINEX Linux Sovereign Suite
      <span class="badge-ver">v4.2.0</span>
    </div>
    <span class="badge-ver" style="color:#22c55e; border-color:rgba(34,197,94,0.3); background:rgba(34,197,94,0.08);">Verified x86_64</span>
  </div>

  <p style="color:var(--text-muted); font-size:14px; margin-bottom:12px;">
    Quick-install the complete sovereign suite (Wallet, P2P Node, and CPU Miner) directly via your terminal:
  </p>

  <div class="terminal-window">
    <div class="terminal-topbar">
      <div class="terminal-dots">
        <span class="term-dot red"></span>
        <span class="term-dot yellow"></span>
        <span class="term-dot green"></span>
      </div>
      <span class="terminal-title">bash — winex-suite-install</span>
      <button class="copy-btn" onclick="copyCli('linux-cmd', this)">
        <svg style="width:14px; height:14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        Copy
      </button>
    </div>
    <div class="cli-box">
      <div class="cli-cmd-wrap">
        <span class="cli-prompt">$</span>
        <span class="cli-cmd" id="linux-cmd">curl -fSsL https://raw.githubusercontent.com/WinexCoin/winex-core/main/scripts/install.sh | bash</span>
      </div>
    </div>
  </div>

  <ul class="suite-info-list" style="margin-top:20px;">
    <li><strong>Verified GitHub Source:</strong> Terminal 1-click installer fetches and verifies the official suite directly from <a href="https://github.com/WinexCoin/winex-core/releases" target="_blank" style="color:var(--accent-cyan); text-decoration:underline;">GitHub Releases (WinexCoin/winex-core)</a>.</li>
    <li>Suite contains: <code>WINEX_Wallet_Linux</code>, <code>WINEX_Node_Linux</code>, <code>WINEX_Miner_Linux</code>.</li>
    <li>Zero external dependencies &bull; Built-in local P2P full node auto-starts with Wallet or Miner.</li>
    <li>Auto-configures desktop entries and terminal command shortcuts in <code>~/.local/bin</code>.</li>
    <li>Minimum Requirements: glibc &ge; 2.28 (Ubuntu 20+, Debian 10+, Fedora 36+, Arch Linux).</li>
  </ul>

  <div class="setup-guide-wrap">
    <div class="setup-guide-title">
      <svg style="width:16px; height:16px; color:#10b981;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
      Quick Installation &amp; Setup Guide
    </div>
    <div class="setup-steps-grid">
      <div class="setup-step-card">
        <span class="step-num">1</span>
        <div class="step-heading">Install via Terminal</div>
        <div class="step-desc">Run the 1-click curl command above. It automatically pulls authenticated binaries from GitHub and places launchers on your desktop.</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">2</span>
        <div class="step-heading">Open Sovereign Wallet</div>
        <div class="step-desc">Installer places shortcuts right onto your <strong>Desktop/WINEX</strong>. Double-click <strong>WINEX Wallet</strong> — it auto-starts your node and creates your secure key.</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">3</span>
        <div class="step-heading">Start Mining (CPU / GPU)</div>
        <div class="step-desc">Double-click <strong>WINEX Miner</strong> on your Desktop, paste your address, choose CPU/GPU mode and intensity to mine blocks.</div>
      </div>
    </div>
  </div>
</div>

<!-- Windows Panel -->
<div id="panel-windows" class="dl-panel">
  <div class="panel-header">
    <div class="panel-title">
      <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M2 3.5L10.5 2.3V11.2H2V3.5M2 12.8H10.5V21.7L2 20.5V12.8M11.8 2.1L22 0.7V11.2H11.8V2.1M11.8 12.8H22V23.3L11.8 21.9V12.8Z"/></svg>
      WINEX Windows Sovereign Suite
      <span class="badge-ver">v4.2.0</span>
    </div>
    <span class="badge-ver" style="color:#22c55e; border-color:rgba(34,197,94,0.3); background:rgba(34,197,94,0.08);">64-bit Windows</span>
  </div>

  <p style="color:var(--text-muted); font-size:14px;">
    Modern 1-Click Setup wizard with clean install options and automatic desktop shortcuts, or portable verified zip suite.
  </p>

  <div class="suite-btn-row" style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
    <a href="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Windows_Setup.zip" class="suite-btn-primary" style="background:#10b981;">
      <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM17 13l-5 5-5-5h3V9h4v4h3z"/></svg>
      Download Setup Wizard (.zip)
    </a>
    <a href="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_Windows_Suite.zip" class="suite-btn-secondary" style="border:1px solid var(--border-strong); padding:10px 18px; border-radius:6px; color:var(--text-main); text-decoration:none; display:inline-flex; align-items:center; gap:8px;">
      <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
      Portable Suite (.zip)
    </a>
  </div>

  <ul class="suite-info-list" style="margin-top:16px;">
    <li><strong>Verified GitHub Source:</strong> Windows releases are hosted on and downloaded directly from <a href="https://github.com/WinexCoin/winex-core/releases" target="_blank" style="color:var(--accent-cyan); text-decoration:underline;">GitHub Releases (WinexCoin/winex-core)</a>.</li>
    <li><strong>WINEX_Setup.exe:</strong> Automated installer wizard with Clean Installation option to safely configure Desktop &amp; Start Menu shortcuts.</li>
    <li><strong>Package Contents:</strong> <code>WINEX_Setup.exe</code>, <code>INSTALL_INSTRUCTIONS.txt</code>, <code>README.txt</code>.</li>
    <li>Compatibility: Windows 10, Windows 11, Windows Server (x86_64). Zero administrator UAC prompt required.</li>
  </ul>

  <div class="setup-guide-wrap">
    <div class="setup-guide-title">
      <svg style="width:16px; height:16px; color:#10b981;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
      Quick Installation &amp; Setup Guide
    </div>
    <div class="setup-steps-grid">
      <div class="setup-step-card">
        <span class="step-num">1</span>
        <div class="step-heading">Download &amp; Extract</div>
        <div class="step-desc">Download <code>WINEX_Windows_Setup.zip</code> and run <code>WINEX_Setup.exe</code>. If Windows SmartScreen appears, click <strong>"More info"</strong> then <strong>"Run anyway"</strong>.</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">2</span>
        <div class="step-heading">Launch Wallet</div>
        <div class="step-desc">Open <strong>WINEX Wallet</strong> from your Desktop or Start Menu. It unlocks your non-custodial vault and syncs to the peer mesh automatically.</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">3</span>
        <div class="step-heading">Run PoW Miner</div>
        <div class="step-desc">Launch <strong>WINEX Miner</strong> from your Desktop shortcut to start dual-pass SHA-256 block creation.</div>
      </div>
    </div>
  </div>
</div>

<!-- macOS Panel (Terminal-First & Suite Package) -->
<div id="panel-macos" class="dl-panel">
  <div class="panel-header">
    <div class="panel-title">
      <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.61 1.34-.55.63-.99 1.66-.86 2.69.98.08 2.01-.52 2.55-1.18z"/></svg>
      WINEX macOS Sovereign Suite
      <span class="badge-ver">v4.2.0</span>
    </div>
    <span class="badge-ver" style="color:#22c55e; border-color:rgba(34,197,94,0.3); background:rgba(34,197,94,0.08);">Universal Apple Silicon &amp; Intel</span>
  </div>

  <p style="color:var(--text-muted); font-size:14px; margin-bottom:12px;">
    Quick-install the complete sovereign suite (Wallet, P2P Node, and CPU/GPU Miner) directly via your macOS Terminal:
  </p>

  <div class="terminal-window">
    <div class="terminal-topbar">
      <div class="terminal-dots">
        <span class="term-dot red"></span>
        <span class="term-dot yellow"></span>
        <span class="term-dot green"></span>
      </div>
      <span class="terminal-title">zsh — winex-suite-macos</span>
      <button class="copy-btn" onclick="copyCli('macos-cmd', this)">
        <svg style="width:14px; height:14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        Copy
      </button>
    </div>
    <div class="cli-box">
      <div class="cli-cmd-wrap">
        <span class="cli-prompt">%</span>
        <span class="cli-cmd" id="macos-cmd">curl -fSsL https://raw.githubusercontent.com/WinexCoin/winex-core/main/scripts/install_mac.sh | bash</span>
      </div>
    </div>
  </div>

  <div class="suite-btn-row">
    <a href="https://github.com/WinexCoin/winex-core/releases/latest/download/WINEX_macOS_Suite.zip" class="suite-btn-primary">
      <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM17 13l-5 5-5-5h3V9h4v4h3z"/></svg>
      Download macOS Suite (.zip)
    </a>
  </div>

  <ul class="suite-info-list">
    <li><strong>Verified GitHub Source:</strong> Universal package hosted on and downloaded directly from <a href="https://github.com/WinexCoin/winex-core/releases" target="_blank" style="color:var(--accent-cyan); text-decoration:underline;">GitHub Releases (WinexCoin/winex-core)</a>.</li>
    <li>Single Universal Archive &bull; Automatically detects and links native <code>arm64</code> (Apple Silicon M1/M2/M3/M4) or <code>amd64</code> (Intel) Mach-O binaries.</li>
    <li>Archive contains: <code>WINEX_Wallet_mac_*</code>, <code>WINEX_Node_mac_*</code>, <code>WINEX_Miner_mac_*</code>, <code>install_mac.sh</code>.</li>
    <li>Zero external dependencies &bull; Built-in local P2P full node auto-starts with Wallet or Miner.</li>
    <li>Compatibility: macOS 11.0 Big Sur and later.</li>
  </ul>

  <div class="setup-guide-wrap">
    <div class="setup-guide-title">
      <svg style="width:16px; height:16px; color:#10b981;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
      Quick Installation &amp; Setup Guide
    </div>
    <div class="setup-steps-grid">
      <div class="setup-step-card">
        <span class="step-num">1</span>
        <div class="step-heading">Install via Terminal or Zip</div>
        <div class="step-desc">Run the 1-click terminal command above, or extract <code>WINEX_macOS_Suite.zip</code> (native for Apple Silicon M1-M4 &amp; Intel).</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">2</span>
        <div class="step-heading">Launch Sovereign Wallet</div>
        <div class="step-desc">The installer sets up your <strong>Desktop/WINEX</strong> folder. Open <strong>WINEX_Wallet</strong> to initialize keys and silent background node.</div>
      </div>
      <div class="setup-step-card">
        <span class="step-num">3</span>
        <div class="step-heading">Start Parallel Mining</div>
        <div class="step-desc">Open <strong>WINEX_Miner</strong> on Desktop, enter your payout address and start parallel CPU/GPU mining.</div>
      </div>
    </div>
  </div>
</div>

<script>
function switchOsTab(os) {
  document.querySelectorAll('.os-pill').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.dl-panel').forEach(el => el.classList.remove('active'));
  
  if (os === 'linux') {
    document.querySelectorAll('.os-pill')[0].classList.add('active');
    document.getElementById('panel-linux').classList.add('active');
  } else if (os === 'windows') {
    document.querySelectorAll('.os-pill')[1].classList.add('active');
    document.getElementById('panel-windows').classList.add('active');
  } else if (os === 'macos') {
    document.querySelectorAll('.os-pill')[2].classList.add('active');
    document.getElementById('panel-macos').classList.add('active');
  }
}
function copyCli(id, btn) {
  const text = document.getElementById(id).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerText;
    btn.innerText = "Copied!";
    setTimeout(() => { btn.innerText = orig; }, 1800);
  });
}
</script>
"""
    return HTMLResponse(render_layout("Download WINEX Core", "download", pro_content))


# ==================== 3. ARCHITECTURE PAGE (/architecture) ====================

@app.get("/architecture", response_class=HTMLResponse)
def architecture_page():
    content = """
<div class="page-intro">
  <h1>System Architecture &amp; Consensus Specifications</h1>
  <p>
    Technical blueprint of the WINEX Layer-1 cryptographic engine, difficulty retargeting math, non-custodial key derivation, and autonomous peer-to-peer gossip topology.
  </p>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Protocol Parameter</th>
        <th>Engineering Specification</th>
        <th>Verification Invariant</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Native Asset Identifier</td>
        <td class="mono" style="color:var(--text-main);">WINEX (WNX)</td>
        <td>Base-layer native coin</td>
      </tr>
      <tr>
        <td>Proof-of-Work Algorithm</td>
        <td class="mono" style="color:var(--text-main);">Double SHA-256 (SHA256d)</td>
        <td>Deterministic header nonce search</td>
      </tr>
      <tr>
        <td>Target Block Cadence</td>
        <td class="mono" style="color:var(--text-main);">900 Seconds (15.0 Minutes)</td>
        <td>Autonomous difficulty retargeting</td>
      </tr>
      <tr>
        <td>Initial Block Subsidy</td>
        <td class="mono" style="color:var(--accent-primary);">40.0000 WNX</td>
        <td>Era 1 (Blocks 1 &rarr; 125,000)</td>
      </tr>
      <tr>
        <td>Halving Epoch Interval</td>
        <td class="mono" style="color:var(--text-main);">Every 125,000 Blocks</td>
        <td>Deterministic 50% subsidy decay</td>
      </tr>
      <tr>
        <td>Issuance Model</td>
        <td class="mono" style="color:var(--accent-secondary);">Algorithmic Halving</td>
        <td>125,000-block halving epochs</td>
      </tr>
      <tr>
        <td>Asymmetric Cryptography</td>
        <td class="mono" style="color:var(--text-main);">SECP256k1 ECDSA</td>
        <td>Client-side non-custodial signing</td>
      </tr>
      <tr>
        <td>Embedded Node Bind</td>
        <td class="mono" style="color:var(--text-main);">http://127.0.0.1:8081</td>
        <td>Auto-started by Wallet &amp; Miner</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Double SHA-256 &amp; Difficulty Retargeting</h2>
    </div>
    <div class="editorial-body">
      <p>
        Every block header commits to the previous block hash, Merkle root of validated transactions, Unix timestamp, target difficulty bits, and a 64-bit nonce. Miners iterate nonces until <code>SHA256(SHA256(BlockHeader))</code> falls below the active target threshold.
      </p>
      <p>
        When aggregate network hashrate expands, the protocol proportionally tightens target difficulty so blocks cannot be mined faster than the 15-minute equilibrium.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Zero-Configuration Peer Gossip</h2>
    </div>
    <div class="editorial-body">
      <p>
        Nodes synchronize state via HTTP/JSON peer exchange (<code>PEX</code>) and deterministic longest-chain verification. Every desktop wallet and miner embeds the full node binary, ensuring automatic local validation and resilient multi-peer block propagation.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Burned Administrative Privileges</h2>
    </div>
    <div class="editorial-body">
      <p>
        The protocol contains no privileged administrator keys, no address blacklists, and no central monetary authority capable of altering the algorithmic emission schedule. Consensus validity is enforced strictly by independent node verification.
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Architecture", "architecture", content)

# ==================== TOKENOMICS PAGE (/tokenomics) ====================

@app.get("/tokenomics", response_class=HTMLResponse)
def tokenomics_page():
    content = """
<div class="page-intro">
  <h1>Tokenomics &amp; Algorithmic Emission Schedule</h1>
  <p>
    Zero pre-mine, zero venture allocations, and 100% Proof-of-Work issuance governed by an immutable halving curve.
  </p>
</div>

<div class="ledger-strip">
  <div class="ledger-cell">
    <div class="ledger-label">Remaining Mineable Pool</div>
    <div id="tokenomicsPool" class="ledger-value" style="color:var(--accent-secondary);">9,998,240 WNX</div>
    <div class="ledger-note">Ready to be mined via PoW</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Initial Block Subsidy</div>
    <div class="ledger-value" style="color:var(--accent-primary);">40.0000 WNX</div>
    <div class="ledger-note">Blocks 1 to 125,000</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Halving Cadence</div>
    <div class="ledger-value">125,000 Blocks</div>
    <div class="ledger-note">900s target block interval</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Pre-Mine / VC Allocation</div>
    <div class="ledger-value" style="color:var(--accent-primary);">0.0000 WNX</div>
    <div class="ledger-note">100% fair PoW distribution</div>
  </div>
</div>

<h2 style="font-size:22px; margin-bottom:18px;">Halving Era Emission Ledger</h2>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Halving Era</th>
        <th>Block Height Range</th>
        <th>Block Subsidy</th>
        <th>Era Emission</th>
        <th>Cumulative Minted</th>
        <th>Supply Share</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Era 1</td>
        <td class="mono">1 &rarr; 125,000</td>
        <td class="mono" style="color:var(--accent-primary);">40.0000 WNX</td>
        <td class="mono">5,000,000.00 WNX</td>
        <td class="mono">5,000,000.00 WNX</td>
        <td class="mono">50.00%</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Era 2</td>
        <td class="mono">125,001 &rarr; 250,000</td>
        <td class="mono">20.0000 WNX</td>
        <td class="mono">2,500,000.00 WNX</td>
        <td class="mono">7,500,000.00 WNX</td>
        <td class="mono">75.00%</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Era 3</td>
        <td class="mono">250,001 &rarr; 375,000</td>
        <td class="mono">10.0000 WNX</td>
        <td class="mono">1,250,000.00 WNX</td>
        <td class="mono">8,750,000.00 WNX</td>
        <td class="mono">87.50%</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Era 4</td>
        <td class="mono">375,001 &rarr; 500,000</td>
        <td class="mono">5.0000 WNX</td>
        <td class="mono">625,000.00 WNX</td>
        <td class="mono">9,375,000.00 WNX</td>
        <td class="mono">93.75%</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Era 5</td>
        <td class="mono">500,001 &rarr; 625,000</td>
        <td class="mono">2.5000 WNX</td>
        <td class="mono">312,500.00 WNX</td>
        <td class="mono">9,687,500.00 WNX</td>
        <td class="mono">96.88%</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main); font-weight:600;">Subsequent Eras</td>
        <td class="mono">625,001 &rarr; Terminal</td>
        <td class="mono">40 &times; 0.5^(era-1)</td>
        <td class="mono">Decaying Subsidy</td>
        <td class="mono">Terminal Emission</td>
        <td class="mono" style="color:var(--accent-primary);">100.00%</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Global Block Competition</h2>
    </div>
    <div class="editorial-body">
      <p>
        Every block is a global cryptographic race. Miners compute double SHA-256 hashes over candidate block headers; the first participant or cooperative pool to discover a valid nonce seals the block and receives the <code>40.0000 WNX</code> coinbase subsidy directly.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Immunity to Premature Depletion</h2>
    </div>
    <div class="editorial-body">
      <p>
        Increased global computing power cannot accelerate the emission schedule. When block discovery intervals drop below 900 seconds, the protocol automatically multiplies cryptographic target difficulty, preserving the mathematical duration of each 125,000-block era.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Solo Validation vs. Pool Aggregation</h2>
    </div>
    <div class="editorial-body">
      <p>
        Solo miners compete directly for the full <code>40.0000 WNX</code> block subsidy per solved height. Cooperative mining pools aggregate hashrate from multiple contributors and distribute solved block rewards proportionally to submitted work shares.
      </p>
    </div>
  </div>
</div>
<script>
async function refreshTkPool() {
  try {
    const res = await fetch('/api/status?t=' + Date.now(), { cache: 'no-store' });
    const s = await res.json();
    if (document.getElementById('tokenomicsPool') && s.pool_remaining != null) {
      document.getElementById('tokenomicsPool').innerText = s.pool_remaining.toLocaleString() + ' WNX';
    }
  } catch(e) {}
}
refreshTkPool();
setInterval(refreshTkPool, 3000);
</script>
"""
    return render_layout("Tokenomics", "tokenomics", content)

# ==================== ROADMAP PAGE (/roadmap) ====================

@app.get("/roadmap", response_class=HTMLResponse)
def roadmap_page():
    content = """
<div class="page-intro">
  <h1>Protocol Engineering Roadmap</h1>
  <p>
    Chronological development milestones across consensus core deployment, native desktop toolchains, Stratum pool infrastructure, and peer-to-peer mesh scaling.
  </p>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Genesis &amp; Consensus Core</h2>
      <div class="mono" style="font-size:13px; color:var(--accent-primary); margin-top:6px;">Completed</div>
    </div>
    <div class="editorial-body">
      <p><strong>Double SHA-256 Consensus Engine:</strong> Implemented deterministic Proof-of-Work block validation with 900-second target cadence and dynamic difficulty retargeting.</p>
      <p><strong>SECP256k1 Non-Custodial Key Architecture:</strong> Deployed client-side elliptic curve keypair generation, BIP-39 seed derivation, and <code>WNX</code> checksum addressing.</p>
      <p><strong>Deterministic Emission Lock:</strong> Hardcoded the 125,000-block halving epochs with burned administrative privileges.</p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Embedded-Node Download &amp; Explorer</h2>
      <div class="mono" style="font-size:13px; color:var(--accent-secondary); margin-top:6px;">Active Deployment</div>
    </div>
    <div class="editorial-body">
      <p><strong>Auto-Node Desktop Packaging:</strong> Embedded background <code>WINEX_Node</code> execution inside Windows (<code>.exe</code>), Linux (<code>.AppImage</code> / ELF), and macOS (<code>.app</code>) wallet and miner suites.</p>
      <p><strong>Live Ledger &amp; RPC Gateway:</strong> Deployed real-time block explorer, balance query endpoints, and HTTP security header hardening (CSP, HSTS, X-Frame-Options).</p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Stratum Pool Daemon &amp; Kademlia Mesh</h2>
      <div class="mono" style="font-size:13px; color:var(--text-muted); margin-top:6px;">Scheduled</div>
    </div>
    <div class="editorial-body">
      <p><strong>Native Stratum Protocol:</strong> Low-latency share validation server for cooperative CPU and GPU mining pools.</p>
      <p><strong>Decentralized Peer Discovery:</strong> Kademlia DHT peer routing and optional SOCKS5/Tor transport privacy.</p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">SPV Light Clients &amp; Atomic Swaps</h2>
      <div class="mono" style="font-size:13px; color:var(--text-muted); margin-top:6px;">Planned</div>
    </div>
    <div class="editorial-body">
      <p><strong>Mobile SPV Wallets:</strong> Simplified Payment Verification clients for iOS and Android with offline hardware signing support and cross-chain HTLC atomic swaps.</p>
    </div>
  </div>
</div>
"""
    return render_layout("Roadmap", "roadmap", content)

# ==================== WHITEPAPER PAGE (/whitepaper) ====================

@app.get("/whitepaper", response_class=HTMLResponse)
def whitepaper_page():
    content = """
<div class="page-intro">
  <h1>WINEX Technical Whitepaper</h1>
  <p>
    A Peer-to-Peer Sovereign Electronic Cash System Built on Deterministic Proof-of-Work Consensus.
  </p>
  <div class="btn-row" style="margin-top:24px;">
    <a href="/whitepaper/download" class="btn-primary">Download Specification (.md)</a>
    <a href="/architecture" class="btn-secondary">View Parameter Table</a>
  </div>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Abstract</h2>
    </div>
    <div class="editorial-body">
      <p>
        WINEX (WNX) is an autonomous, decentralized cryptocurrency protocol engineered to provide non-custodial electronic cash without centralized intermediaries, pre-mined allocations, or corporate administrative keys. The network operates strictly on Proof-of-Work consensus utilizing double SHA-256 computation, enforcing mathematical scarcity with periodic halving epochs.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Proof-of-Work &amp; Difficulty Equilibrium</h2>
    </div>
    <div class="editorial-body">
      <p>
        Network consensus is achieved through Nakamoto Proof-of-Work. Blocks are chained cryptographically via <code>SHA256(SHA256(BlockHeader))</code> with a target block interval of 900 seconds (15 minutes).
      </p>
      <p>
        The protocol continuously recalculates target difficulty based on observed block velocity. If aggregate hashrate increases, cryptographic difficulty scales proportionately so that 125,000-block halving epochs remain locked to their mathematical cadence.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Monetary Issuance Equation</h2>
    </div>
    <div class="editorial-body">
      <p>
        Starting with an initial coinbase subsidy of <code>40.0000 WNX</code> per block, the reward halves every <code>125,000 blocks</code>:
      </p>
      <p class="mono" style="padding:14px 18px; background:var(--bg-surface); border:1px solid var(--border-line); color:var(--accent-primary);">
        Subsidy(h) = 40.0000 &times; (0.5) ^ floor(h / 125000)
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">SECP256k1 Key Custody &amp; Embedded Node Mesh</h2>
    </div>
    <div class="editorial-body">
      <p>
        Private keys are generated client-side on the SECP256k1 elliptic curve using CSPRNG entropy. Public addresses are derived via SHA-256 and RIPEMD-160 hashing with native <code>WNX</code> prefixing. Every desktop wallet and miner embeds the full node validator on port <code>8081</code>, forming an autonomous peer-to-peer relay mesh.
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Whitepaper", "whitepaper", content)

@app.get("/whitepaper/download")
def whitepaper_download():
    wp_text = """# WINEX Technical Specification
## A Peer-to-Peer Sovereign Electronic Cash System

### Protocol Parameters
- Currency Name: WINEX (WNX)
- Consensus Algorithm: Double SHA-256 Proof-of-Work
- Target Block Time: 900 seconds (15 minutes)
- Monetary Model: Deflationary Halving Subsidy
- Pre-mine: 0 WNX (0%)
- Initial Block Reward: 40.0000 WNX
- Halving Epoch: Every 125,000 blocks
- Signature Scheme: SECP256k1 ECDSA
- Embedded Node Port: 127.0.0.1:8081
- Governance: Autonomous, burned developer keys

### Issuance Equation
Reward(block_height) = 40.0000 * (0.5 ** floor(block_height / 125000))

### Privacy & Legal Classification
- Non-custodial client-side key generation.
- Zero KYC, zero identity registration, GDPR/KVKK data minimization by design.
- Distributed AS-IS under the MIT Open-Source License.
"""
    return HTMLResponse(content=wp_text, media_type="text/markdown", headers={"Content-Disposition": "attachment; filename=WINEX_Whitepaper.md"})

# ==================== LEGAL, REGULATORY & COMPLIANCE PAGES (/legal, /privacy, /terms) ====================

@app.get("/legal", response_class=HTMLResponse)
def legal_page():
    content = """
<div class="page-intro">
  <h1>Regulatory Compliance, Risk Disclosures &amp; Open-Source Notices</h1>
  <p>
    Mandatory legal disclosures, software warranty disclaimers, international regulatory classification (MiCA, SEC, SPK, GDPR/KVKK), and third-party open-source license attributions governing the WINEX protocol and client software.
  </p>
</div>

<div class="editorial-section" style="border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px; padding: 28px; margin-bottom: 36px;">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title" style="color: var(--accent-secondary);">GLOBAL REGULATORY STANDING &amp; PROTOCOL CLASSIFICATION</h2>
    </div>
    <div class="editorial-body">
      <p>
        WINEX Core and the official portal <strong>https://winexcoin.com</strong> operate under strict decentralized open-source principles, data sovereignty, and international regulatory alignment across all global jurisdictions:
      </p>

      <p>
        <strong>1. Universal Jurisdictional Alignment (All Continents):</strong><br>
        WINEX (WNX) is an autonomous, open-source Layer-1 Proof-of-Work software protocol engineered and distributed strictly in compliance with global computing standards:
      </p>
      <ul style="padding-left: 20px; line-height: 1.7; color: var(--text-body); margin: 8px 0 16px;">
        <li><strong>European Union (EU MiCA &amp; GDPR):</strong> Fully complies with EU Markets in Crypto-Assets (MiCA) decentralization criteria. WNX operates without a centralized issuer, foundation treasury, or asset-referenced backing. Fully adheres to GDPR data minimization.</li>
        <li><strong>United States (SEC &amp; FinCEN):</strong> Satisfies decentralized commodity standards under the Howey test—zero pre-mine, zero token sales, and zero reliance on managerial efforts of an enterprise. Not a money transmitter under FinCEN non-custodial software guidance.</li>
        <li><strong>United Kingdom &amp; Switzerland:</strong> Meets UK Financial Conduct Authority (FCA) criteria for unbacked exchange/utility tokens and Swiss FINMA utility token guidelines.</li>
        <li><strong>Turkey &amp; Regional Frameworks:</strong> Complies with Capital Markets Law No. 6362 &amp; 7518 and MASAK regulations. WINEX is strictly <em>NOT</em> a Crypto Asset Service Provider (CASP), custodial depository, broker-dealer, or fund manager.</li>
        <li><strong>Asia-Pacific &amp; Global (Japan FSA, Singapore MAS):</strong> Decentralized peer-to-peer computing software. Pure mining consensus with zero centralized custodial operations.</li>
      </ul>

      <p>
        <strong>2. Zero Fundraising, Pre-Mine, or Deposit Collection:</strong><br>
        WINEX has never conducted an Initial Coin Offering (ICO), Initial Exchange Offering (IEO), token pre-sale, or venture capital seed round. The network does NOT accept, hold, or solicit fiat currencies (USD, EUR, TRY, GBP, JPY) or cryptocurrencies.
      </p>

      <p>
        <strong>3. No Profit Guarantees or Investment Contracts:</strong><br>
        No person or institution is ever offered dividends, interest, passive yields, capital gains, or value appreciation promises. Proof-of-Work mining and node validation are strictly computational and cryptographic activities.
      </p>

      <p>
        <strong>4. Consumer Protection &amp; Brand Advisory:</strong><br>
        WINEX Core developers will <strong>NEVER</strong> send unsolicited direct messages, solicit funds, sell tokens privately, or request wallet seed phrases. Furthermore, WINEX (WNX) has <strong>no affiliation whatsoever</strong> with third parties operating forex brokerages, CFD trading portals, or financial investment programs under the "Winex" name.
      </p>

      <p>
        <strong>5. Non-Custodial Architecture &amp; Data Sovereignty:</strong><br>
        Private keys and BIP-39 seed phrases are generated locally using device CSPRNG entropy. Zero personal identifiers, zero KYC, and zero telemetry are stored or transmitted.
      </p>

      <p style="margin-top: 16px; font-size: 13.5px; color: var(--text-muted);">
        Official Verification Desk: <a href="mailto:support@winexcoin.com" style="color:var(--accent-secondary);">support@winexcoin.com</a> &bull; Official Web Portal: <a href="https://winexcoin.com" style="color:var(--accent-secondary);">https://winexcoin.com</a>
      </p>
    </div>
  </div>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Non-Financial Instrument &amp; Protocol Nature</h2>
    </div>
    <div class="editorial-body">
      <p>
        WINEX (WNX) is a decentralized, open-source Layer-1 Proof-of-Work cryptographic software protocol. WNX units are generated exclusively by independent nodes solving SHA-256 computational puzzles.
      </p>
      <p>
        No Initial Coin Offering (ICO), Initial Exchange Offering (IEO), token pre-sale, venture capital distribution, or pooled investment contract has ever been conducted. WNX does not represent equity, debt, shares, voting rights, or a claim on revenue against any legal entity, foundation, or developer group under EU Markets in Crypto-Assets (MiCA), US Securities Act (Howey test), or Turkish Capital Markets Board (SPK) frameworks.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">No Investment, Financial, Legal, or Tax Advice</h2>
    </div>
    <div class="editorial-body">
      <p>
        All content, technical whitepapers, emission tables, and telemetry published on this portal are provided strictly for informational, cryptographic, and systems-engineering purposes. Nothing herein constitutes an offer to sell, a solicitation to buy, or a recommendation regarding any financial instrument.
      </p>
      <p>
        Cryptographic digital assets and Proof-of-Work computation carry substantial technical, operational, electricity, and market volatility risks. Users should consult qualified legal, tax, and financial professionals in their respective jurisdictions before running mining hardware or interacting with peer-to-peer networks.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Non-Custodial Architecture &amp; Irreversibility</h2>
    </div>
    <div class="editorial-body">
      <p>
        The WINEX Wallet and Node suite is strictly non-custodial. Cryptographic private keys and BIP-39 recovery phrases are generated locally on user hardware and are never transmitted to any server.
      </p>
      <p>
        Because no central authority or administrator key exists, lost private keys, forgotten keystore passwords, or mistakenly broadcast on-chain transactions <strong>cannot be recovered, reversed, frozen, or modified</strong> by anyone.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">GDPR &amp; KVKK Privacy-by-Design Compliance</h2>
    </div>
    <div class="editorial-body">
      <p>
        In accordance with Regulation (EU) 2016/679 (General Data Protection Regulation — GDPR) and Law No. 6698 on the Protection of Personal Data (KVKK), this portal and the WINEX software enforce strict data minimization:
      </p>
      <p>
        1. Zero collection of names, email addresses, phone numbers, or government identifiers.<br>
        2. Zero advertising trackers, behavioral profiling cookies, or third-party analytics pixels.<br>
        3. Public blockchain records consist solely of pseudonymous cryptographic addresses (<code>WNX...</code>) and transaction hashes broadcast voluntarily by network peers.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Jurisdictional Compliance &amp; User Responsibility</h2>
    </div>
    <div class="editorial-body">
      <p>
        Users downloading, compiling, or operating WINEX node, wallet, or mining software are solely responsible for determining whether such activities are lawful in their jurisdiction of residence, including compliance with local tax reporting, energy regulations, and cryptographic software import/export restrictions.
      </p>
    </div>
  </div>

  <div class="editorial-row" id="oss-notices">
    <div>
      <h2 class="editorial-title">Open-Source Software &amp; Third-Party Notices</h2>
    </div>
    <div class="editorial-body">
      <p>
        The WINEX Core Protocol and client suite incorporate and acknowledge the following open-source components and licenses:
      </p>
      <p>
        &bull; <strong>WINEX Core Protocol &amp; Go Miner:</strong> Released under the MIT License. Provided &ldquo;AS IS&rdquo;, without warranty of any kind, express or implied.<br>
        &bull; <strong>Go Standard Library:</strong> Copyright The Go Authors. Licensed under the BSD 3-Clause License.<br>
        &bull; <strong>Python Runtime &amp; FastAPI / Uvicorn:</strong> Licensed under the PSF License Agreement and MIT License.<br>
        &bull; <strong>Qt6 / PySide6 Desktop GUI Framework:</strong> Dynamically linked under the GNU Lesser General Public License v3 (LGPLv3).<br>
        &bull; <strong>3D WebGL Engine:</strong> Three.js (MIT License).<br>
        &bull; <strong>Design System &amp; Typography Specification:</strong> Interface craft principles informed by Impeccable by Paul Bakaus (MIT / Apache 2.0) and Google Fonts (Sora &amp; JetBrains Mono, OFL-1.1).
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Legal & Regulatory Compliance", "legal", content)

@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    content = """
<div class="page-intro">
  <h1>Privacy Policy &amp; Data Sovereignty (GDPR / KVKK)</h1>
  <p>
    Effective Date: October 2026. Architectural guarantees regarding personal data non-collection, local key custody, and public ledger transparency.
  </p>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">No Personal Data Processing</h2>
    </div>
    <div class="editorial-body">
      <p>
        The WINEX protocol, desktop client suite, and web portal do not collect, store, process, or monetize personal identifying information (PII). No user accounts, email databases, KYC portals, or telemetry profiles exist.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Client-Side Cryptographic Isolation</h2>
    </div>
    <div class="editorial-body">
      <p>
        All SECP256k1 private keys and mnemonic recovery phrases are generated locally on your machine. Private keys never leave your hardware and are never transmitted over RPC calls.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Zero Tracking Cookies</h2>
    </div>
    <div class="editorial-body">
      <p>
        This website does not set advertising cookies, cross-site tracking pixels, or behavioral fingerprinting scripts.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Immutable On-Chain Records</h2>
    </div>
    <div class="editorial-body">
      <p>
        Transactions and blocks broadcast to the decentralized peer-to-peer network are permanently recorded on the public blockchain ledger as pseudonymous cryptographic addresses and SHA-256 digests.
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Privacy Policy", "privacy", content)

@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    content = """
<div class="page-intro">
  <h1>Terms of Use &amp; MIT Open-Source License</h1>
  <p>
    Effective Date: October 2026. Legal terms governing the use of the WINEX open-source software suite, cryptographic protocol, and public RPC endpoints.
  </p>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">AS-IS Software Warranty Disclaimer</h2>
    </div>
    <div class="editorial-body">
      <p>
        THE SOFTWARE IS PROVIDED &ldquo;AS IS&rdquo;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Absolute User Responsibility for Private Keys</h2>
    </div>
    <div class="editorial-body">
      <p>
        You acknowledge that WINEX is an autonomous, non-custodial network. You bear sole responsibility for backing up your private keys, seed words, and wallet files. Protocol developers cannot recover lost credentials or reverse confirmed transactions.
      </p>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Absence of Investment Contract or Profit Guarantee</h2>
    </div>
    <div class="editorial-body">
      <p>
        Running a WINEX node, miner, or wallet is a technical and computational activity. No fiat price, exchange listing, liquidity, or financial return is promised or guaranteed. See full <a href="/legal" style="color:var(--accent-secondary);">Regulatory &amp; Legal Disclosures</a>.
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Terms of Service", "terms", content)

# ==================== CONTACT & SUPPORT (/contact) ====================

@app.get("/contact", response_class=HTMLResponse)
def contact_page():
    content = """
<div class="page-intro">
  <h1>Official Contact &amp; Support Desk</h1>
  <p>
    Direct communication channels for protocol contributors, node operators, independent miners, security researchers, and institutional partners.
  </p>
</div>

<div class="editorial-section" style="border: 1px solid rgba(56, 189, 248, 0.4); background: rgba(56, 189, 248, 0.04); border-radius: 8px; padding: 28px; margin-bottom: 36px;">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title" style="color: #38bdf8;">OFFICIAL COMMUNICATION DESK</h2>
    </div>
    <div class="editorial-body">
      <p>
        The sole verified official communication address for the WINEX Core Protocol and web infrastructure is:
      </p>
      <div style="margin: 18px 0; padding: 18px 24px; background: rgba(0,0,0,0.5); border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.35); display: inline-block;">
        <span style="font-size: 13px; color: var(--text-muted); display: block; margin-bottom: 6px; letter-spacing: 0.05em; text-transform: uppercase;">Primary Inquiries &amp; Technical Support:</span>
        <a href="mailto:support@winexcoin.com" style="font-size: 20px; font-weight: 700; color: #38bdf8; text-decoration: none; font-family: var(--font-mono, monospace);">
          support@winexcoin.com
        </a>
      </div>
      <p style="font-size: 14px; color: var(--text-muted); line-height: 1.6;">
        Official Web: <a href="https://winexcoin.com" style="color: var(--accent-secondary);">https://winexcoin.com</a> &bull; Response Time: Typically within 24-48 business hours.
      </p>
    </div>
  </div>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h3 class="editorial-title">Inquiry Channels</h3>
    </div>
    <div class="editorial-body">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div style="padding: 20px; border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px;">
          <h4 style="margin: 0 0 8px; color: var(--text-main); font-size: 15px; font-weight: 600;">Technical &amp; Node Support</h4>
          <p style="font-size: 13.5px; color: var(--text-muted); margin: 0; line-height: 1.6;">
            Assistance with running consensus nodes, P2P mesh discovery configurations, and RPC telemetry queries.
          </p>
        </div>
        <div style="padding: 20px; border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px;">
          <h4 style="margin: 0 0 8px; color: var(--text-main); font-size: 15px; font-weight: 600;">Mining &amp; Hardware Diagnostics</h4>
          <p style="font-size: 13.5px; color: var(--text-muted); margin: 0; line-height: 1.6;">
            Troubleshooting OpenCL/GPU driver detection, CPU thread tuning, and PoW submission metrics.
          </p>
        </div>
        <div style="padding: 20px; border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px;">
          <h4 style="margin: 0 0 8px; color: var(--text-main); font-size: 15px; font-weight: 600;">Vulnerability &amp; Security Disclosure</h4>
          <p style="font-size: 13.5px; color: var(--text-muted); margin: 0; line-height: 1.6;">
            Responsible cryptographic disclosures, consensus edge-case bug bounties, and network security reports.
          </p>
        </div>
        <div style="padding: 20px; border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px;">
          <h4 style="margin: 0 0 8px; color: var(--text-main); font-size: 15px; font-weight: 600;">Institutional &amp; Legal Verification</h4>
          <p style="font-size: 13.5px; color: var(--text-muted); margin: 0; line-height: 1.6;">
            Licensing verifications, MIT open-source attributions, and non-custodial compliance documentation.
          </p>
        </div>
      </div>
    </div>
  </div>

  <div class="editorial-row" style="margin-top: 36px; border-top: 1px solid var(--border-line); padding-top: 28px;">
    <div>
      <h3 class="editorial-title" style="color: var(--accent-secondary);">Security &amp; Fraud Prevention Advisory</h3>
    </div>
    <div class="editorial-body">
      <p>
        <strong>PROTECT YOURSELF AGAINST FRAUD AND IMPERSONATORS:</strong>
      </p>
      <ul style="padding-left: 20px; line-height: 1.8; color: var(--text-body); font-size: 14.5px;">
        <li>The WINEX team will <strong>NEVER</strong> send unsolicited direct messages (DMs) on Telegram, Discord, X, or email.</li>
        <li>We will <strong>NEVER</strong> ask for funds, wire transfers, crypto deposits, or your private wallet seed phrases.</li>
        <li>We do <strong>NOT</strong> operate managed investment schemes, cloud-mining contracts, or guaranteed return programs.</li>
        <li>Always verify that emails originate strictly from <code>@winexcoin.com</code> and web access is on <code>https://winexcoin.com</code>.</li>
      </ul>
      <p style="margin-top: 16px;">
        For comprehensive regulatory details, visit our <a href="/legal" style="color: var(--accent-secondary); font-weight: 600;">Regulatory &amp; Legal Disclosures &rarr;</a>
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("Contact & Support", "contact", content)

# ==================== ABOUT & DISAMBIGUATION (/about, /api/about) ====================

@app.get("/about", response_class=HTMLResponse)
def about_page():
    content = """
<div class="page-intro">
  <h1>About WINEX (WNX) Protocol</h1>
  <p>
    An independent, sovereign Layer-1 Proof-of-Work cryptocurrency protocol engineered for verifiable mathematical scarcity, non-custodial sovereignty, and zero-dependency peer-to-peer settlement.
  </p>
</div>

<div class="editorial-section" style="border: 1px solid var(--border-line); background: var(--bg-surface); border-radius: 8px; padding: 24px; margin-bottom: 32px;">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title" style="color: var(--accent-secondary);">GLOBAL IDENTITY &amp; BRAND CLARIFICATION</h2>
    </div>
    <div class="editorial-body">
      <p>
        <strong>Notice for Search Engines, AI Models &amp; Investors:</strong><br>
        WINEX (symbol: <strong>WNX</strong> | Website: <a href="https://winexcoin.com" style="color:var(--accent-secondary);">https://winexcoin.com</a>) is an open-source Layer-1 Proof-of-Work blockchain protocol.
      </p>
      <p>
        WINEX (WNX) has <strong>NO relationship, connection, or association</strong> with any entities operating under the name "Winex Markets", unauthorized forex brokerages, CFD trading portals, or financial investment schemes. WINEX Core never solicits deposits, never provides investment advice, and operates solely as open-source computational software under the MIT License.
      </p>
    </div>
  </div>
</div>

<div class="editorial-section">
  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Core Architecture &amp; Tokenomics</h2>
    </div>
    <div class="editorial-body">
      <p>
        WINEX operates as an autonomous, self-balancing Layer-1 blockchain network:
      </p>
      <ul>
        <li><strong>Consensus Mechanism:</strong> Deterministic Double-Pass SHA-256 Proof-of-Work.</li>
        <li><strong>Monetary Model:</strong> Algorithmic block subsidy halving every 125,000 blocks.</li>
        <li><strong>Initial Block Subsidy:</strong> 40.0000 WNX per block.</li>
        <li><strong>Halving Epochs:</strong> Halving occurs every 125,000 blocks (~3.5 years).</li>
        <li><strong>Target Block Time:</strong> 15 minutes (900 seconds) with retargeting window.</li>
        <li><strong>Zero Pre-mine &amp; Burned Master Keys:</strong> Fair genesis launch with zero developer pre-mine and zero venture capital allocations.</li>
        <li><strong>Privacy &amp; Security:</strong> SECP256k1 elliptic curve cryptography, BIP-39 mnemonic derivation, AES-256-GCM encrypted keystore, zero KYC.</li>
      </ul>
    </div>
  </div>

  <div class="editorial-row">
    <div>
      <h2 class="editorial-title">Official Inquiries &amp; Support</h2>
    </div>
    <div class="editorial-body">
      <p>
        Official Portal: <a href="https://winexcoin.com" style="color:var(--accent-secondary);">https://winexcoin.com</a><br>
        Technical Support &amp; Listing Inquiries: <a href="mailto:support@winexcoin.com" style="color:var(--accent-secondary);">support@winexcoin.com</a><br>
        Source Code: MIT Open-Source Protocol
      </p>
    </div>
  </div>
</div>
"""
    return render_layout("About WINEX", "about", content)

@app.get("/api/about")
def api_about():
    return {
        "project": "WINEX (WNX)",
        "protocol": "Autonomous Layer-1 Proof-of-Work",
        "official_website": "https://winexcoin.com",
        "official_email": "support@winexcoin.com",
        "finite_cap": 10000000.0,
        "initial_subsidy": 40.0,
        "halving_interval": 125000,
        "block_time_seconds": 900.0,
        "license": "MIT",
        "disambiguation": "WINEX (WNX) is an independent open-source Layer-1 blockchain protocol and has ZERO affiliation with 'Winex Markets' or any forex trading platforms.",
        "legal_status": {
            "regulatory_classification": "Autonomous non-custodial open-source software. Not a Crypto Asset Service Provider (CASP) or financial intermediary. No funds, deposits, or investments accepted.",
            "anti_fraud_notice": "Zero token sales, zero fundraising, zero profit guarantees. Official developers never DM or solicit capital."
        }
    }

# ==================== 4. TELEMETRY PAGE (/telemetry) ====================

@app.get("/telemetry", response_class=HTMLResponse)
def telemetry_page():
    content = """
<style>
  .query-panel {
    border: 1px solid var(--border-line);
    background: var(--bg-surface);
    padding: 32px;
    margin-bottom: 56px;
  }
  .query-form {
    display: flex;
    gap: 12px;
    margin-top: 16px;
  }
  @media (max-width: 640px) {
    .query-form { flex-direction: column; }
  }
  .query-input {
    flex: 1;
    background: var(--bg-canvas);
    border: 1px solid var(--border-strong);
    padding: 13px 16px;
    color: var(--text-main);
    font-family: var(--font-mono);
    font-size: 14px;
    border-radius: 4px;
  }
  .query-output {
    display: none;
    margin-top: 16px;
    padding: 14px 18px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    font-family: var(--font-mono);
    font-size: 14px;
    color: var(--accent-primary);
  }
</style>

<div class="page-intro">
  <h1>Node Telemetry &amp; RPC Interface</h1>
  <p>
    Real-time consensus metrics from the Layer-1 state machine, interactive on-chain address balance verification, and public HTTP RPC specifications.
  </p>
</div>

<div class="ledger-strip">
  <div class="ledger-cell">
    <div class="ledger-label">Current Block Height</div>
    <div id="blockHeight" class="ledger-value">#...</div>
    <div class="ledger-note">Target cadence: 900s</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Active Block Subsidy</div>
    <div id="blockReward" class="ledger-value" style="color:var(--accent-primary);">... WNX</div>
    <div class="ledger-note">Halves every 125,000 blocks</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Remaining Mineable Pool</div>
    <div id="poolAvailable" class="ledger-value" style="color:var(--accent-secondary);">... WNX</div>
    <div id="poolAvailableSub" class="ledger-note">Mined: 1,760 WNX</div>
  </div>
  <div class="ledger-cell">
    <div class="ledger-label">Active Mesh Peers</div>
    <div id="peerCount" class="ledger-value" style="color:var(--accent-secondary);">...</div>
    <div class="ledger-note">Autonomous P2P gossip</div>
  </div>
</div>

<section class="query-panel" aria-labelledby="balance-query-heading">
  <h2 id="balance-query-heading" style="font-size:20px;">On-Chain Address Balance Verification</h2>
  <p style="font-size:14px; color:var(--text-muted); margin-top:6px;">Query confirmed UTXO/account state directly from the Layer-1 ledger.</p>
  <div class="query-form">
    <label for="addressInput" style="position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0);">WNX Wallet Address</label>
    <input type="text" id="addressInput" class="query-input" placeholder="Enter WNX address (e.g. WNX...)" />
    <button type="button" class="btn-primary" onclick="checkBalance()">Verify Balance</button>
  </div>
  <div id="balanceDisplay" class="query-output"></div>
</section>

<h2 style="font-size:22px; margin-bottom:18px;">Public HTTP JSON-RPC Endpoints</h2>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>HTTP Method &amp; Route</th>
        <th>Response Payload</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="mono" style="color:var(--text-main);">GET /api/status</td>
        <td>Returns current block height, active block reward, remaining PoW pool, difficulty, and peer count.</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main);">GET /api/blocks?limit=25</td>
        <td>Returns confirmed blocks ordered by height descending with SHA-256 hashes and transaction counts.</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main);">GET /api/balance/{address}</td>
        <td>Returns confirmed WNX balance for the specified cryptographic address.</td>
      </tr>
      <tr>
        <td class="mono" style="color:var(--text-main);">POST /api/tx/send</td>
        <td>Validates SECP256k1 signature and broadcasts a signed transaction to the mempool.</td>
      </tr>
    </tbody>
  </table>
</div>

<script>
async function checkBalance() {
  const addr = document.getElementById('addressInput').value.trim();
  const resBox = document.getElementById('balanceDisplay');
  if (!addr) return;
  resBox.style.display = 'block';
  resBox.innerText = 'Querying ledger state...';
  try {
    const res = await fetch('/api/balance/' + encodeURIComponent(addr));
    const data = await res.json();
    resBox.innerText = 'Confirmed Balance: ' + Number(data.balance).toFixed(4) + ' WNX';
  } catch (e) {
    resBox.innerText = 'Unable to query address state.';
  }
}

async function pollTelemetry() {
  try {
    const res = await fetch('/api/status');
    const d = await res.json();
    document.getElementById('blockHeight').innerText = '#' + d.block_height;
    document.getElementById('blockReward').innerText = d.block_reward.toFixed(4) + ' WNX';
    document.getElementById('poolAvailable').innerText = (d.pool_remaining != null ? d.pool_remaining.toLocaleString() : '9,998,240') + ' WNX';
    if (document.getElementById('poolAvailableSub')) document.getElementById('poolAvailableSub').innerText = 'Mined: ' + (d.mined_circulation != null ? d.mined_circulation.toLocaleString() : '1,760') + ' WNX';
    document.getElementById('peerCount').innerText = d.peer_count + ' Nodes';
  } catch (e) {}
}

pollTelemetry();
setInterval(pollTelemetry, 4000);
</script>
"""
    return render_layout("Telemetry", "telemetry", content)

# ==================== 5. EXPLORER PAGE (/explorer) ====================

@app.get("/explorer", response_class=HTMLResponse)
def explorer_page():
    content = """
<div class="page-intro">
  <h1>Blockchain Ledger Explorer</h1>
  <p>
    Live cryptographic block ledger verifying height sequence, SHA-256 block digests, coinbase miner recipients, and confirmed transaction counts.
  </p>
</div>

<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; flex-wrap:wrap; gap:12px;">
  <h2 style="font-size:20px;">Confirmed Mainnet Blocks</h2>
  <span class="mono" style="font-size:13px; color:var(--accent-primary); font-weight:600;">LIVE LEDGER STREAM (3s POLL)</span>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Height</th>
        <th>Block SHA-256 Digest</th>
        <th>Coinbase Miner</th>
        <th>Transactions</th>
        <th>UTC / Local Time</th>
      </tr>
    </thead>
    <tbody id="blocksTable">
      <tr><td colspan="5" class="mono" style="padding:28px; color:var(--text-muted);">Synchronizing block headers from local node...</td></tr>
    </tbody>
  </table>
</div>

<script>
async function pollBlocks() {
  try {
    const bRes = await fetch('/api/blocks?limit=25');
    const blocks = await bRes.json();
    const tb = document.getElementById('blocksTable');
    if (blocks && blocks.length > 0) {
      tb.innerHTML = blocks.map(b => `
        <tr>
          <td class="mono" style="color:var(--text-main); font-weight:600;">#${b.block_index}</td>
          <td class="mono" style="color:var(--text-muted);">${b.hash.substring(0, 24)}...</td>
          <td class="mono" style="color:#ffffff; font-size:12.5px; font-weight:600; user-select:all;">${b.miner || 'COINBASE'}</td>
          <td class="mono" style="color:var(--accent-primary);">${b.tx_count || 1}</td>
          <td class="mono" style="color:var(--text-muted);">${new Date(b.timestamp * 1000).toLocaleTimeString()}</td>
        </tr>
      `).join('');
    }
  } catch (e) {}
}

pollBlocks();
setInterval(pollBlocks, 3000);
</script>
"""
    return render_layout("Explorer", "explorer", content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("winex_api:app", host="0.0.0.0", port=8080, reload=False)
