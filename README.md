# WINEX Core (WNX)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8.svg?logo=go)](https://golang.org)
[![Consensus: PoW](https://img.shields.io/badge/Consensus-SHA--256%20PoW-orange.svg)](#consensus-protocol)
[![Halving Schedule](https://img.shields.io/badge/Halving-125%2C000%20Blocks-indigo.svg)](#economic-model)

**WINEX** is an autonomous, decentralized Layer-1 proof-of-work blockchain network engineered for long-term cryptographic scarcity, deterministic block issuance, and sovereign peer-to-peer digital settlement.

---

## Key Highlights

- **Capped Scarcity:** Strictly enforced maximum limit of **12,100,000 WNX** (2,100,000 Genesis Reserve + 10,000,000 PoW Mining Subsidy Pool).
- **Predictable Halving Protocol:** Block rewards begin at **40.0 WNX** and halve every **125,000 blocks** (~3.56 years).
- **Deterministic SHA-256 PoW:** ASIC/GPU-resistant double-pass SHA-256 with address-bound salting and dynamic Emergency Difficulty Adjustment (EDA).
- **Sovereign Non-Custodial Security:** BIP-39 deterministic seed phrase generation, cold AES-256-GCM vault encryption, and zero third-party dependencies.
- **Mesh NAT-P2P Traversal:** Automatic UPnP router mapping and LAN multicast discovery (`239.255.255.250:1900`) for seamless peer connectivity across NAT/firewalls.

---

## Repository Architecture

```
WINEX_Core/
├── cmd/
│   ├── winex-node/         # Standalone Layer-1 P2P node daemon & consensus engine
│   ├── winex-wallet/       # Sovereign desktop wallet with AES-256-GCM cold vault
│   └── winex-miner/        # Dedicated GPU (OpenCL 3.0) & Multi-Core CPU mining engine
├── docs/
│   ├── ARCHITECTURE.md     # Detailed systems architecture & component flows
│   ├── CONSENSUS_SPEC.md   # Mathematical consensus & halving specifications
│   └── RPC_API.md          # Complete JSON-RPC 2.0 & REST API documentation
├── scripts/
│   ├── build_all.sh        # Unified cross-platform builder
│   ├── build_node.sh       # Node compiler
│   ├── build_wallet.sh     # Desktop wallet compiler
│   ├── build_miner.sh      # OpenCL/CPU miner compiler
│   └── build_windows.bat   # Windows native build script
├── go.work                 # Multi-module Go workspace
├── LICENSE                 # Standard MIT open-source license
├── SECURITY.md             # Responsible disclosure & vulnerability policy
└── CONTRIBUTING.md         # Contribution guidelines & code standards
```

---

## Economic Model & Consensus Rules

| Metric | Specification |
| :--- | :--- |
| **Consensus Algorithm** | Double-Pass Salted SHA-256 Proof-of-Work |
| **Target Block Interval** | 15.0 Minutes (900 seconds) |
| **Initial Block Reward** | 40.0 WNX |
| **Halving Interval** | Every 125,000 blocks |
| **Total Unmined Pool** | 10,000,000 WNX |
| **Genesis Reserve** | 2,100,000 WNX |
| **Total Lifetime Supply** | 12,100,000 WNX |
| **Reorganization Guard** | Max Reorg Depth: 10 blocks |

---

## Quick Start: Building From Source

### Prerequisites
- **Go 1.23+** installed (`go version`).
- **OpenCL headers & drivers** (optional, required only for native GPU OpenCL mining).
- **Git**

### 1. Clone & Build All Components
```bash
git clone https://github.com/Winexcoin/winex-core.git
cd winex-core

# Make compilation scripts executable
chmod +x scripts/*.sh

# Build all binaries (Node, Wallet, Miner)
./scripts/build_all.sh
```
All compiled executables will be placed in the `bin/` directory.

---

## Running WINEX Components

### 1. Launching the Layer-1 Node (`winex-node`)
Run a sovereign full node daemon:
```bash
./bin/winex-node
```
Options:
- `--host <ip>` : Address to bind to (default: `127.0.0.1`, use `0.0.0.0` for public validator relays).
- `--port <port>` : HTTP and RPC listen port (default: `8081`).
- `--daemon` : Run in headless background daemon mode.

Verify node status via JSON-RPC:
```bash
curl -s -X POST http://127.0.0.1:8081/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}'
```

### 2. Launching the Desktop Wallet (`winex-wallet`)
Start the sovereign desktop wallet:
```bash
./bin/winex-wallet
```
- Automatically generates a BIP-39 12-word seed phrase or imports an existing vault.
- Encrypts keys in memory and on disk using AES-256-GCM with PBKDF2 (100,000 rounds).
- Provides instant transaction signing and multi-account HD balance management.

### 3. Launching the Dedicated Miner (`winex-miner`)
Connect to the decentralized mesh and mine blocks:
```bash
# CPU Mining (Automatic worker optimization)
./bin/winex-miner --device=cpu --intensity=3

# Dedicated OpenCL GPU Mining
./bin/winex-miner --device=gpu --intensity=5
```
Options:
- `--device <gpu|cpu>` : Hardware execution device.
- `--intensity <1-5>` : Compute intensity profile (1=Eco, 3=Optimal, 5=Max).
- `--threads <n>` : Number of CPU worker goroutines (defaults to all CPU cores).
- `--node <url>` : Connect to a specific local or remote validator node.

---

## Security & Auditing

The WINEX Core codebase has been engineered and audited with the following security guarantees:
- **Constant-Time Verification:** Public key comparisons and CSRF tokens employ `crypto/subtle.ConstantTimeCompare` to eliminate timing side-channel attacks.
- **SSRF Defense:** Peer discovery rigorously validates all peer addresses, blocking IPv4/IPv6 private subnets (RFC 1918), loopback, link-local, and internal domain patterns.
- **Mempool Replay Guard:** Digital signatures are registered in deduplication stores to strictly prevent transaction replay.
- **Strict Input Limiting:** All HTTP body decoders utilize `http.MaxBytesReader` to defend against denial-of-service memory exhaustion.

For vulnerability reports, review our [Security Policy](SECURITY.md) or contact `support@winexcoin.com`.

---

## License

WINEX Core is released under the permissive [MIT License](LICENSE).
Copyright (c) 2026 WINEX Core Contributors & Foundation.
