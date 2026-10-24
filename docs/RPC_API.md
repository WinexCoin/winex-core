# WINEX Node RPC & REST API Reference

The WINEX daemon (`winex-node`) exposes both a Bitcoin-compatible JSON-RPC interface and a high-performance REST API.

Default Listen Port: `8081`  
Default Bind Address: `127.0.0.1` (use `--host 0.0.0.0` for public node relays)

---

## JSON-RPC 2.0 (`/rpc` or `/api/rpc`)

Send an HTTP `POST` request with `Content-Type: application/json`.

### Supported Methods

#### 1. `getinfo` / `getnetworkinfo`
Returns current blockchain status, block height, total mined circulation, and active peers.
```json
{"jsonrpc": "2.0", "method": "getinfo", "params": [], "id": 1}
```

#### 2. `getblockcount`
Returns the integer height of the longest chain.
```json
{"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1}
```

#### 3. `getbestblockhash`
Returns the 64-character hex hash of the current tip block.
```json
{"jsonrpc": "2.0", "method": "getbestblockhash", "params": [], "id": 1}
```

#### 4. `getblock`
Retrieves block details by index or 64-character hex hash.
```json
{"jsonrpc": "2.0", "method": "getblock", "params": [42], "id": 1}
```

#### 5. `getbalance`
Retrieves confirmed and pending balances for a given WNX wallet address.
```json
{"jsonrpc": "2.0", "method": "getbalance", "params": ["WNX..."], "id": 1}
```

#### 6. `getmininginfo`
Returns current block mining template, target difficulty, reward, and server time.
```json
{"jsonrpc": "2.0", "method": "getmininginfo", "params": [], "id": 1}
```

---

## REST Endpoints

### `GET /api/status`
Returns high-level chain status:
```json
{
  "status": "online",
  "block_height": 45,
  "mined_circulation": 1800.0,
  "pool_remaining": 9998200.0,
  "difficulty": 6,
  "active_peers": 4
}
```

### `GET /api/balance/{address}`
Returns wallet balance for `{address}`:
```json
{
  "address": "WNX...",
  "balance": 120.0000,
  "unmined_pool": 9998200.0
}
```

### `GET /api/mining/template`
Returns the active mining template for miners to compute nonces:
```json
{
  "block_index": 46,
  "prev_hash": "000000abc...",
  "merkle_root": "e3b0c442...",
  "difficulty": 6,
  "target": "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "block_reward": 40.0,
  "pool_remaining": 9998200.0,
  "server_time": 1740000000.123
}
```

### `POST /api/mining/submit`
Submits a newly solved PoW block candidate:
```json
{
  "miner_address": "WNX...",
  "block_index": 46,
  "nonce": 1284729,
  "timestamp": 1740000000.123,
  "hash": "000000abc...",
  "reported_hash": "000000abc..."
}
```

### `POST /api/transaction/send`
Submits a signed ECDSA secp256k1 transaction:
```json
{
  "sender": "WNX...",
  "recipient": "WNX...",
  "amount": 10.5000,
  "fee": 0.0010,
  "public_key": "<64-byte hex>",
  "signature": "<64-byte hex>",
  "timestamp": 1740000000.123
}
```
