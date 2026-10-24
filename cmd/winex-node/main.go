package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	genesisVaultAddr  = "WNX5B15097CB2203643C472AB992FA9FB1A"
	genesisSupply     = 2100000.0
	initialPool       = 10000000.0
	initialReward     = 40.0
	halvingInterval   = 125000
	defaultDifficulty = 6
	genesisHash       = "00003789c9e082b2310f3212f4af4aa6daded8d3e8861285ea6c74fd37cfd1a4"
	MaxReorgDepth     = 10
)

var bootstrapNodes = []string{
	"https://winexcoin.com",
}

type Block struct {
	Index      int64   `json:"block_index"`
	PrevHash   string  `json:"prev_hash"`
	MerkleRoot string  `json:"merkle_root"`
	Miner      string  `json:"miner"`
	Difficulty int     `json:"difficulty"`
	Nonce      int64   `json:"nonce"`
	Timestamp  float64 `json:"timestamp"`
	Hash       string  `json:"hash"`
	Reward     float64 `json:"reward"`
	TxCount    int     `json:"tx_count"`
}

type Transaction struct {
	TxID      string  `json:"tx_id"`
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
	Fee       float64 `json:"fee"`
	Timestamp float64 `json:"timestamp"`
	Signature string  `json:"signature"`
	PublicKey string  `json:"public_key"`
}

type BlockchainState struct {
	Blocks        []Block            `json:"blocks"`
	Balances      map[string]float64 `json:"balances"`
	PoolRemaining float64            `json:"pool_remaining"`
	Mempool       []Transaction      `json:"mempool"`
	SeenSigs      map[string]bool    `json:"seen_sigs"`
	Peers         []string           `json:"peers"`
}

type NodeEngine struct {
	mu       sync.RWMutex
	state    BlockchainState
	dataPath string
}

func getBlockReward(height int64) float64 {
	if height <= 0 {
		return 0.0
	}
	eras := (height - 1) / halvingInterval
	if eras >= 64 {
		return 0.0
	}
	reward := initialReward / math.Pow(2.0, float64(eras))
	if reward < 1e-6 {
		return 0.0
	}
	return math.Round(reward*1e6) / 1e6
}

func isSafePublicPeer(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || h == "0.0.0.0" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".onion") {
		return false
	}
	ip := net.ParseIP(h)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func verifyTransactionSignature(pubKeyHex, sender, recip string, amount, fee float64, ts float64, sigHex string) bool {
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != 64 {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != 64 {
		return false
	}

	addrHash := sha256.Sum256(pubBytes)
	expectedSender := "WNX" + strings.ToUpper(hex.EncodeToString(addrHash[:16]))
	if expectedSender != sender {
		return false
	}

	uncompressed := append([]byte{0x04}, pubBytes...)
	pubKey, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return false
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	candidateMessages := []string{
		fmt.Sprintf("%s:%s:%.8f:%.8f:%.4f", sender, recip, amount, fee, ts),
		fmt.Sprintf("%s:%s:%.8f:%.8f:%v", sender, recip, amount, fee, ts),
		fmt.Sprintf("%s:%s:%.4f:%.4f:%.4f", sender, recip, amount, fee, ts),
		fmt.Sprintf("%s:%s:%.4f:%.4f:%v", sender, recip, amount, fee, ts),
		fmt.Sprintf("%s:%s:%.8f:%.8f", sender, recip, amount, fee),
		fmt.Sprintf("%s:%s:%.4f:%.4f", sender, recip, amount, fee),
		fmt.Sprintf("%s:%s:%v:%v", sender, recip, amount, fee),
	}

	for _, msg := range candidateMessages {
		h256 := sha256.Sum256([]byte(msg))
		if ecdsa.Verify(pubKey.ToECDSA(), h256[:], r, s) {
			return true
		}
	}
	return false
}

func getHomeDataDir() string {
	appData := os.Getenv("APPDATA")
	if appData != "" {
		return filepath.Join(appData, "WINEX")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".winex")
}

func NewNodeEngine(dataPath string) *NodeEngine {
	n := &NodeEngine{
		dataPath: dataPath,
		state: BlockchainState{
			Blocks:        []Block{},
			Balances:      make(map[string]float64),
			PoolRemaining: initialPool,
			Mempool:       []Transaction{},
			SeenSigs:      make(map[string]bool),
			Peers:         []string{},
		},
	}
	n.loadOrInitGenesis()
	return n
}

func (n *NodeEngine) loadOrInitGenesis() {
	_ = os.MkdirAll(filepath.Dir(n.dataPath), 0700)

	if b, err := os.ReadFile(n.dataPath); err == nil {
		var s BlockchainState
		if err := json.Unmarshal(b, &s); err == nil && len(s.Blocks) > 0 {
			n.state = s
			if n.state.Balances == nil {
				n.state.Balances = make(map[string]float64)
			}
			if n.state.SeenSigs == nil {
				n.state.SeenSigs = make(map[string]bool)
			}
			if n.state.PoolRemaining < 5000000.1 && len(n.state.Blocks) <= 2 {
				n.state.PoolRemaining = initialPool
			}
			for i := range n.state.Blocks {
				if n.state.Blocks[i].Index > 0 {
					if n.state.Blocks[i].Reward <= 0 {
						n.state.Blocks[i].Reward = getBlockReward(n.state.Blocks[i].Index)
					}
					if strings.TrimSpace(n.state.Blocks[i].Miner) == "" {
						n.state.Blocks[i].Miner = "WNX8D4B5CED15F50A144899A8B3551C8CD4"
					}
				}
			}
			return
		}
	}

	genesis := Block{
		Index:      0,
		PrevHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		MerkleRoot: "0000000000000000000000000000000000000000000000000000000000000000",
		Miner:      genesisVaultAddr,
		Difficulty: defaultDifficulty,
		Nonce:      0,
		Timestamp:  1740000000.0,
		Hash:       genesisHash,
		Reward:     genesisSupply,
		TxCount:    1,
	}
	n.state.Blocks = append(n.state.Blocks, genesis)
	n.state.Balances[genesisVaultAddr] = genesisSupply
	n.state.PoolRemaining = initialPool
	n.saveToDisk()
}

func (n *NodeEngine) saveToDisk() {
	b, err := json.MarshalIndent(n.state, "", "  ")
	if err == nil {
		_ = os.WriteFile(n.dataPath, b, 0600)
	}
}

func computePowHash(index int64, prevHash, merkle, minerAddr string, timestamp float64, nonce int64) string {
	raw := fmt.Sprintf("%d:%s:%s:%s:%.4f:%d", index, prevHash, merkle, minerAddr, timestamp, nonce)
	h1 := sha256.Sum256([]byte(raw))
	h1Hex := hex.EncodeToString(h1[:])

	saltPrefix := raw
	if len(raw) > 16 {
		saltPrefix = raw[:16]
	}
	hSalt := sha256.Sum256([]byte(minerAddr + saltPrefix))
	saltHex := hex.EncodeToString(hSalt[:])

	h2 := sha256.Sum256([]byte(h1Hex + saltHex))
	return hex.EncodeToString(h2[:])
}

func (n *NodeEngine) computeDeterministicMerkle(index int64) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("block_%d_merkle", index))
	for _, tx := range n.state.Mempool {
		parts = append(parts, tx.TxID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

func (n *NodeEngine) GetStatus() map[string]interface{} {
	n.mu.RLock()
	height := int64(len(n.state.Blocks))
	latestHash := genesisHash
	if height > 0 {
		latestHash = n.state.Blocks[height-1].Hash
	}
	poolRem := n.state.PoolRemaining
	memCount := len(n.state.Mempool)
	peerCount := len(n.state.Peers)
	n.mu.RUnlock()

	reward := getBlockReward(height)
	if reward <= 0 {
		reward = initialReward
	}

	return map[string]interface{}{
		"coin_name":             "WINEX",
		"symbol":                "WNX",
		"status":                "online",
		"node":                  "WINEX Sovereign Standalone L1 Node",
		"block_height":          height,
		"latest_hash":           latestHash,
		"difficulty":            defaultDifficulty,
		"difficulty_target":     "000000000c370000000000000000000000000000000000000000000000000000",
		"difficulty_multiplier": 1.0,
		"block_reward":          reward,
		"mining_pool_available": poolRem,
		"pool_remaining":        poolRem,
		"mempool_tx_count":      memCount,
		"peer_count":            peerCount,
		"timestamp":             time.Now().Unix(),
	}
}

func (n *NodeEngine) GetBalance(addr string) map[string]interface{} {
	addr = strings.TrimSpace(addr)
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	for _, boot := range bootstrapNodes {
		resp, err := client.Get(strings.TrimRight(boot, "/") + "/api/balance/" + addr)
		if err == nil && resp.StatusCode == 200 {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()
			if err == nil {
				var remoteBal map[string]interface{}
				if json.Unmarshal(body, &remoteBal) == nil {
					if bVal, ok := remoteBal["balance"].(float64); ok {
						n.mu.Lock()
						n.state.Balances[addr] = bVal
						n.mu.Unlock()
						return remoteBal
					}
				}
			}
		}
	}

	n.mu.RLock()
	defer n.mu.RUnlock()
	bal := n.state.Balances[addr]
	return map[string]interface{}{
		"address":      addr,
		"balance":      bal,
		"block_height": len(n.state.Blocks),
	}
}

func (n *NodeEngine) GetMiningTemplate() map[string]interface{} {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	for _, boot := range bootstrapNodes {
		resp, err := client.Get(strings.TrimRight(boot, "/") + "/api/mining/template")
		if err == nil && resp.StatusCode == 200 {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
			resp.Body.Close()
			if err == nil {
				var tmpl map[string]interface{}
				if json.Unmarshal(body, &tmpl) == nil && tmpl["block_index"] != nil {
					return tmpl
				}
			}
		}
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	idx := int64(len(n.state.Blocks))
	prev := genesisHash
	if idx > 0 {
		prev = n.state.Blocks[idx-1].Hash
	}

	merkle := n.computeDeterministicMerkle(idx)
	reward := math.Min(getBlockReward(idx), n.state.PoolRemaining)

	return map[string]interface{}{
		"block_index":           idx,
		"prev_hash":             prev,
		"merkle_root":           merkle,
		"difficulty":            defaultDifficulty,
		"target":                "000000000c370000000000000000000000000000000000000000000000000000",
		"target_prefix":         "00000000",
		"difficulty_multiplier": 1.0,
		"reward":                reward,
		"pool_remaining":        n.state.PoolRemaining,
		"tx_count":              len(n.state.Mempool),
	}
}

func (n *NodeEngine) SubmitBlock(minerAddr string, index, nonce int64, ts float64, submittedHash string) (bool, string) {
	minerAddr = strings.TrimSpace(minerAddr)
	if !strings.HasPrefix(minerAddr, "WNX") || len(minerAddr) < 20 || len(minerAddr) > 42 {
		return false, "Invalid miner wallet address"
	}
	if !strings.HasPrefix(submittedHash, "000000") || len(submittedHash) != 64 {
		return false, "Invalid PoW hash difficulty"
	}

	// Relay block candidate to global mesh first
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"miner_address": minerAddr,
		"block_index":   index,
		"nonce":         nonce,
		"timestamp":     ts,
		"hash":          submittedHash,
		"reported_hash": submittedHash,
	})
	n.mu.Lock()
	defer n.mu.Unlock()

	curHeight := int64(len(n.state.Blocks))
	if index < curHeight {
		return false, fmt.Sprintf("Stale block index: expected >= %d, got %d", curHeight, index)
	}

	prev := genesisHash
	if curHeight > 0 {
		lastBlock := n.state.Blocks[curHeight-1]
		prev = lastBlock.Hash
		if ts < lastBlock.Timestamp-60.0 {
			return false, "Block timestamp cannot be older than previous block"
		}
	}
	now := float64(time.Now().UnixNano()) / 1e9
	if ts > now+7200.0 {
		return false, "Block timestamp cannot be more than 2 hours in the future"
	}

	merkle := n.computeDeterministicMerkle(index)
	computed := computePowHash(index, prev, merkle, minerAddr, ts, nonce)
	if computed != submittedHash {
		return false, "Invalid PoW Solution: computed hash mismatch"
	}
	if !strings.HasPrefix(computed, "000000") {
		return false, "Invalid PoW Solution: hash does not satisfy target difficulty"
	}

	go func() {
		client := &http.Client{Timeout: 3500 * time.Millisecond}
		for _, boot := range bootstrapNodes {
			resp, err := client.Post(strings.TrimRight(boot, "/")+"/api/mining/submit", "application/json", bytes.NewReader(payloadBytes))
			if err == nil {
				resp.Body.Close()
			}
		}
	}()

	reward := math.Min(getBlockReward(index), n.state.PoolRemaining)
	b := Block{
		Index:      index,
		PrevHash:   prev,
		MerkleRoot: merkle,
		Miner:      minerAddr,
		Difficulty: defaultDifficulty,
		Nonce:      nonce,
		Timestamp:  ts,
		Hash:       submittedHash,
		Reward:     reward,
		TxCount:    len(n.state.Mempool) + 1,
	}
	n.state.Blocks = append(n.state.Blocks, b)
	n.state.Balances[minerAddr] += reward
	if n.state.PoolRemaining >= reward {
		n.state.PoolRemaining -= reward
	}
	n.state.Mempool = []Transaction{}
	n.saveToDisk()

	return true, fmt.Sprintf("Block #%d verified and committed to ledger", index)
}

func (n *NodeEngine) AddTransaction(sender, recip string, amount, fee float64, pubKey, sig string, ts float64) (bool, string) {
	sender = strings.TrimSpace(sender)
	recip = strings.TrimSpace(recip)
	pubKey = strings.TrimSpace(pubKey)
	sig = strings.TrimSpace(sig)

	if math.IsNaN(amount) || math.IsInf(amount, 0) || amount < 0.00000001 || amount > initialPool {
		return false, "Invalid transfer amount (minimum 0.00000001 WNX)"
	}
	if math.IsNaN(fee) || math.IsInf(fee, 0) || fee < 0.0 || fee > 1000.0 {
		return false, "Invalid fee parameter"
	}
	if !strings.HasPrefix(sender, "WNX") || !strings.HasPrefix(recip, "WNX") || len(recip) < 20 || len(recip) > 42 {
		return false, "Invalid WNX address format"
	}
	if sender == recip {
		return false, "Self-transfers are prohibited"
	}

	now := float64(time.Now().UnixNano()) / 1e9
	if ts < now-86400.0 || ts > now+7200.0 {
		return false, "Transaction timestamp drift out of bounds"
	}

	pubBytes, err := hex.DecodeString(pubKey)
	if err != nil || len(pubBytes) != 64 {
		return false, "Invalid 64-byte public key hex"
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil || len(sigBytes) != 64 {
		return false, "Invalid 64-byte signature hex"
	}
	addrHash := sha256.Sum256(pubBytes)
	expectedSender := "WNX" + strings.ToUpper(hex.EncodeToString(addrHash[:16]))
	if expectedSender != sender {
		return false, "Public key does not match sender address"
	}

	if !verifyTransactionSignature(pubKey, sender, recip, amount, fee, ts, sig) {
		return false, "Invalid cryptographic transaction signature"
	}

	// Relay to global consensus gateway
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"sender":     sender,
		"recipient":  recip,
		"amount":     amount,
		"fee":        fee,
		"public_key": pubKey,
		"signature":  sig,
		"timestamp":  ts,
	})
	client := &http.Client{Timeout: 3500 * time.Millisecond}
	for _, boot := range bootstrapNodes {
		resp, err := client.Post(strings.TrimRight(boot, "/")+"/api/transaction/send", "application/json", bytes.NewReader(payloadBytes))
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var rMap map[string]interface{}
				if json.Unmarshal(body, &rMap) == nil {
					if txID, ok := rMap["tx_id"].(string); ok && txID != "" {
						return true, txID
					}
				}
			}
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.state.Mempool) >= 10000 {
		return false, "Mempool congestion: maximum pending capacity reached (10,000 txs)"
	}

	if n.state.SeenSigs[sig] {
		return false, "Replay protection: duplicate signature rejected"
	}

	senderBal := n.state.Balances[sender]
	totalReq := amount + fee
	if senderBal < totalReq {
		return false, fmt.Sprintf("Insufficient balance: available %.4f WNX, required %.4f WNX", senderBal, totalReq)
	}

	txidRaw := fmt.Sprintf("%s:%s:%.8f:%.8f:%.4f:%s", sender, recip, amount, fee, ts, sig)
	txid := fmt.Sprintf("%x", sha256.Sum256([]byte(txidRaw)))

	n.state.SeenSigs[sig] = true
	n.state.Balances[sender] = math.Round((senderBal-totalReq)*1e8) / 1e8
	n.state.Balances[recip] = math.Round((n.state.Balances[recip]+amount)*1e8) / 1e8

	tx := Transaction{
		TxID:      txid,
		Sender:    sender,
		Recipient: recip,
		Amount:    amount,
		Fee:       fee,
		Timestamp: ts,
		Signature: sig,
		PublicKey: pubKey,
	}
	n.state.Mempool = append(n.state.Mempool, tx)
	n.saveToDisk()

	return true, txid
}

func (n *NodeEngine) StartGlobalPeerMesh(listenPort int) {
	go func() {
		client := &http.Client{Timeout: 4 * time.Second}
		for {
			for _, boot := range bootstrapNodes {
				boot = strings.TrimRight(boot, "/")

				regPayload := map[string]string{
					"peer_url": fmt.Sprintf("auto:%d", listenPort),
				}
				regBody, _ := json.Marshal(regPayload)
				respReg, errReg := client.Post(boot+"/p2p/register", "application/json", bytes.NewReader(regBody))
				if errReg == nil {
					respReg.Body.Close()
				}

				// Sync canonical full block ledger & pool remaining from global seed
				reqBlk, _ := http.NewRequest("GET", boot+"/api/blocks", nil)
				reqBlk.Header.Set("User-Agent", "WINEX-Node/3.6.0 (Global-Mesh)")
				respBlk, errBlk := client.Do(reqBlk)
				if errBlk == nil && respBlk.StatusCode == 200 {
					var incomingBlocks []Block
					if json.NewDecoder(io.LimitReader(respBlk.Body, 524288)).Decode(&incomingBlocks) == nil && len(incomingBlocks) > 0 {
						if len(incomingBlocks) > 1 && incomingBlocks[0].Index > incomingBlocks[len(incomingBlocks)-1].Index {
							for i, j := 0, len(incomingBlocks)-1; i < j; i, j = i+1, j-1 {
								incomingBlocks[i], incomingBlocks[j] = incomingBlocks[j], incomingBlocks[i]
							}
						}
						n.mu.Lock()
						if len(incomingBlocks) > len(n.state.Blocks) {
							// Enforce MaxReorgDepth protection against 51% reorg attacks
							commonAncestor := -1
							minLen := len(n.state.Blocks)
							if len(incomingBlocks) < minLen {
								minLen = len(incomingBlocks)
							}
							for i := 0; i < minLen; i++ {
								if n.state.Blocks[i].Hash == incomingBlocks[i].Hash {
									commonAncestor = i
								} else {
									break
								}
							}
							reorgDepth := len(n.state.Blocks) - (commonAncestor + 1)
							if len(n.state.Blocks) > 0 && commonAncestor >= 0 && reorgDepth > MaxReorgDepth {
								fmt.Printf("\n \033[38;2;239;68;68m[SECURITY ALERT]\033[0m Deep reorganization attempt rejected: depth %d exceeds MaxReorgDepth (%d)\n", reorgDepth, MaxReorgDepth)
							} else {
								// Validate cryptographic continuity
								valid := true
								startIdx := 0
								if commonAncestor >= 0 {
									startIdx = commonAncestor + 1
								}
								for k := startIdx; k < len(incomingBlocks); k++ {
									if k > 0 && incomingBlocks[k].PrevHash != incomingBlocks[k-1].Hash {
										valid = false
										break
									}
								}
								if valid {
									n.state.Blocks = incomingBlocks
									n.saveToDisk()
								}
							}
						}
						n.mu.Unlock()
					}
					respBlk.Body.Close()
				}

				respSt, errSt := client.Get(boot + "/api/status")
				if errSt == nil {
					var st struct {
						BlockHeight int64   
						PoolRem     float64 
					}
					if json.NewDecoder(io.LimitReader(respSt.Body, 32768)).Decode(&st) == nil && st.BlockHeight > 0 {
						n.mu.Lock()
						if st.PoolRem > 0 {
							n.state.PoolRemaining = st.PoolRem
						}
						n.mu.Unlock()
					}
					respSt.Body.Close()
				}

				resp, err := client.Get(boot + "/p2p/peers")
				if err == nil {
					var pData struct {
						Peers []string `json:"peers"`
					}
					if json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&pData) == nil {
						n.mu.Lock()
						for _, p := range pData.Peers {
							p = strings.TrimSpace(p)
							if !isSafePublicPeer(p) {
								continue
							}
							exists := false
							for _, known := range n.state.Peers {
								if known == p {
									exists = true
									break
								}
							}
							if !exists && len(n.state.Peers) < 64 {
								n.state.Peers = append(n.state.Peers, p)
							}
						}
						n.mu.Unlock()
					}
					resp.Body.Close()
				}
			}

			// P2P Direct Mesh Sync (Independent of VDS/Web)
			n.mu.RLock()
			activePeers := make([]string, len(n.state.Peers))
			copy(activePeers, n.state.Peers)
			n.mu.RUnlock()

			for _, peer := range activePeers {
				peer = strings.TrimRight(peer, "/")
				if peer == "" {
					continue
				}
				respBlk, errBlk := client.Get(peer + "/api/blocks?limit=50")
				if errBlk == nil && respBlk.StatusCode == 200 {
					var remoteBlocks []struct {
						Index      int64   `json:"block_index"`
						Hash       string  `json:"hash"`
						PrevHash   string  `json:"prev_hash"`
						Nonce      int64   `json:"nonce"`
						Difficulty int     `json:"difficulty"`
						Timestamp  float64 `json:"timestamp"`
						TxCount    int     `json:"tx_count"`
						Miner      string  `json:"miner"`
						Reward     float64 `json:"reward"`
					}
					if json.NewDecoder(io.LimitReader(respBlk.Body, 65536)).Decode(&remoteBlocks) == nil && len(remoteBlocks) > 0 {
						n.mu.Lock()
						for i := len(remoteBlocks) - 1; i >= 0; i-- {
							rb := remoteBlocks[i]
							if rb.Index <= 0 {
								continue
							}
							reward := rb.Reward
							if reward <= 0 {
								reward = getBlockReward(rb.Index)
							}
							miner := strings.TrimSpace(rb.Miner)
							if miner == "" {
								miner = genesisVaultAddr
							}

							exists := false
							for idx, eb := range n.state.Blocks {
								if eb.Index == rb.Index {
									if n.state.Blocks[idx].Miner == "" || n.state.Blocks[idx].Reward <= 0 {
										n.state.Blocks[idx].Miner = miner
										n.state.Blocks[idx].Reward = reward
										n.state.Blocks[idx].Hash = rb.Hash
									}
									exists = true
									break
								}
							}
							if !exists {
								n.state.Blocks = append(n.state.Blocks, Block{
									Index:      rb.Index,
									PrevHash:   rb.PrevHash,
									Miner:      miner,
									Difficulty: rb.Difficulty,
									Nonce:      rb.Nonce,
									Timestamp:  rb.Timestamp,
									Hash:       rb.Hash,
									Reward:     reward,
									TxCount:    rb.TxCount,
								})
							}
						}
						n.saveToDisk()
						n.mu.Unlock()
					}
					respBlk.Body.Close()
				}
			}

			time.Sleep(12 * time.Second)
		}
	}()
}

func writeJSON(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func main() {
	ensureInteractiveTerminal()

	var port = flag.Int("port", 8081, "Node HTTP listen port")
	var host = flag.String("host", "127.0.0.1", "Node listen address (use 0.0.0.0 for public relay)")
	var daemon = flag.Bool("daemon", false, "Run as headless background P2P daemon")
	flag.Parse()
	_ = daemon

	dataPath := filepath.Join(getHomeDataDir(), "chain.state.json")
	engine := NewNodeEngine(dataPath)
	engine.StartGlobalPeerMesh(*port)

	// Autonomous Decentralized NAT Traversal & Auto-Discovery
	TryAutoUPnP(*port)
	StartLANAutoDiscovery(engine, *port)

	mux := http.NewServeMux()

	handleStatus := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, engine.GetStatus(), 200)
	}
	mux.HandleFunc("/stats", handleStatus)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/state", handleStatus)
	mux.HandleFunc("/api/blockchain/info", handleStatus)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			handleStatus(w, r)
			return
		}
		writeJSON(w, map[string]string{"error": "Endpoint not found"}, 404)
	})

	mux.HandleFunc("/api/balance/", func(w http.ResponseWriter, r *http.Request) {
		addr := strings.TrimPrefix(r.URL.Path, "/api/balance/")
		addr = strings.TrimSpace(addr)
		writeJSON(w, engine.GetBalance(addr), 200)
	})

	mux.HandleFunc("/api/supply", func(w http.ResponseWriter, r *http.Request) {
		st := engine.GetStatus()
		writeJSON(w, map[string]interface{}{
			"max_supply":            10000000.0,
			"circulating_supply":    st["mined_circulation"],
			"unmined_pool_remaining": st["pool_remaining"],
			"initial_block_reward":  40.0,
			"current_block_reward":  st["block_reward"],
			"halving_interval":      125000,
		}, 200)
	})

	handleRPC := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		var req struct {
			JSONRPC string        `json:"jsonrpc"`
			Method  string        `json:"method"`
			Params  []interface{} `json:"params"`
			ID      interface{}   `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "error": map[string]interface{}{"code": -32700, "message": "Parse error"}, "id": nil}, 400)
			return
		}
		method := strings.ToLower(strings.TrimSpace(req.Method))
		rpcOK := func(res interface{}) {
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "result": res, "id": req.ID}, 200)
		}
		rpcErr := func(code int, msg string) {
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "error": map[string]interface{}{"code": code, "message": msg}, "id": req.ID}, 200)
		}

		switch method {
		case "getblockcount", "getheight":
			engine.mu.RLock()
			h := int64(len(engine.state.Blocks))
			engine.mu.RUnlock()
			rpcOK(h)
		case "getbestblockhash":
			engine.mu.RLock()
			hash := ""
			if len(engine.state.Blocks) > 0 {
				hash = engine.state.Blocks[len(engine.state.Blocks)-1].Hash
			}
			engine.mu.RUnlock()
			rpcOK(hash)
		case "getblock":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing block height or hash")
				return
			}
			q := fmt.Sprintf("%v", req.Params[0])
			engine.mu.RLock()
			var found *Block
			h := int64(len(engine.state.Blocks))
			for i := range engine.state.Blocks {
				b := &engine.state.Blocks[i]
				if fmt.Sprintf("%d", b.Index) == q || strings.EqualFold(b.Hash, q) {
					found = b
					break
				}
			}
			engine.mu.RUnlock()
			if found == nil {
				rpcErr(-5, "Block not found")
				return
			}
			confs := h - found.Index + 1
			if confs < 1 {
				confs = 1
			}
			rpcOK(map[string]interface{}{
				"block_index":   found.Index,
				"hash":          found.Hash,
				"prev_hash":     found.PrevHash,
				"merkle_root":   found.MerkleRoot,
				"nonce":         found.Nonce,
				"difficulty":    found.Difficulty,
				"timestamp":     found.Timestamp,
				"miner":         found.Miner,
				"reward":        found.Reward,
				"tx_count":      found.TxCount,
				"confirmations": confs,
			})
		case "getbalance":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing address parameter")
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			rpcOK(engine.GetBalance(addr))
		case "validateaddress":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing address parameter")
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			valid := len(addr) == 35 && strings.HasPrefix(addr, "WNX")
			rpcOK(map[string]interface{}{"isvalid": valid, "address": addr})
		case "getmininginfo":
			rpcOK(engine.GetMiningTemplate())
		case "getnetworkinfo", "getinfo":
			rpcOK(engine.GetStatus())
		case "getpeerinfo":
			engine.mu.RLock()
			peers := engine.state.Peers
			engine.mu.RUnlock()
			rpcOK(peers)
		default:
			// Forward complex queries (tx/address lookup) to bootstrap archival seed if needed
			client := &http.Client{Timeout: 4 * time.Second}
			b, _ := json.Marshal(req)
			for _, boot := range bootstrapNodes {
				resp, err := client.Post(strings.TrimRight(boot, "/")+"/rpc", "application/json", bytes.NewReader(b))
				if err == nil && resp.StatusCode == 200 {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
					resp.Body.Close()
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(200)
					_, _ = w.Write(body)
					return
				}
			}
			rpcErr(-32601, "Method not found")
		}
	}
	mux.HandleFunc("/rpc", handleRPC)
	mux.HandleFunc("/api/rpc", handleRPC)

	handleBlocks := func(w http.ResponseWriter, r *http.Request) {
		engine.mu.RLock()
		total := len(engine.state.Blocks)
		blks := make([]Block, 0, 50)
		for i := total - 1; i >= 0 && len(blks) < 50; i-- {
			blks = append(blks, engine.state.Blocks[i])
		}
		engine.mu.RUnlock()
		writeJSON(w, blks, 200)
	}
	mux.HandleFunc("/api/blocks", handleBlocks)
	mux.HandleFunc("/api/chain", handleBlocks)

	handleTxs := func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{Timeout: 2500 * time.Millisecond}
		for _, boot := range bootstrapNodes {
			resp, err := client.Get(strings.TrimRight(boot, "/") + "/api/transactions/recent?limit=25")
			if err == nil && resp.StatusCode == 200 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				if err == nil {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(200)
					_, _ = w.Write(body)
					return
				}
			}
		}
		engine.mu.RLock()
		txs := engine.state.Mempool
		engine.mu.RUnlock()
		writeJSON(w, txs, 200)
	}
	mux.HandleFunc("/api/transactions", handleTxs)
	mux.HandleFunc("/api/transactions/recent", handleTxs)

	mux.HandleFunc("/api/mining/template", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, engine.GetMiningTemplate(), 200)
	})

	mux.HandleFunc("/api/mining/submit", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		var req struct {
			MinerAddress string  `json:"miner_address"`
			BlockIndex   int64   `json:"block_index"`
			Nonce        int64   `json:"nonce"`
			Timestamp    float64 `json:"timestamp"`
			Hash         string  `json:"hash"`
			ReportedHash string  `json:"reported_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]string{"error": "Invalid payload"}, 400)
			return
		}
		submittedHash := strings.TrimSpace(req.Hash)
		if submittedHash == "" {
			submittedHash = strings.TrimSpace(req.ReportedHash)
		}
		ok, msg := engine.SubmitBlock(req.MinerAddress, req.BlockIndex, req.Nonce, req.Timestamp, submittedHash)
		if ok {
			writeJSON(w, map[string]interface{}{"status": "accepted", "success": true, "message": msg}, 200)
		} else {
			writeJSON(w, map[string]interface{}{"status": "rejected", "success": false, "message": msg}, 400)
		}
	})

	handleTxSend := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		var req struct {
			Sender    string  `json:"sender"`
			Recipient string  `json:"recipient"`
			Amount    float64 `json:"amount"`
			Fee       float64 `json:"fee"`
			PublicKey string  `json:"public_key"`
			Signature string  `json:"signature"`
			Timestamp float64 `json:"timestamp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]string{"error": "Invalid payload"}, 400)
			return
		}
		ok, res := engine.AddTransaction(req.Sender, req.Recipient, req.Amount, req.Fee, req.PublicKey, req.Signature, req.Timestamp)
		if ok {
			writeJSON(w, map[string]interface{}{"status": "ok", "success": true, "tx_id": res}, 200)
		} else {
			writeJSON(w, map[string]interface{}{"status": "error", "detail": res, "message": res}, 400)
		}
	}
	mux.HandleFunc("/api/tx/send", handleTxSend)
	mux.HandleFunc("/api/transaction/send", handleTxSend)

	handlePeers := func(w http.ResponseWriter, r *http.Request) {
		engine.mu.RLock()
		peers := engine.state.Peers
		engine.mu.RUnlock()
		writeJSON(w, map[string]interface{}{"peers": peers, "count": len(peers)}, 200)
	}
	mux.HandleFunc("/api/peers", handlePeers)
	mux.HandleFunc("/api/p2p/peers", handlePeers)
	mux.HandleFunc("/p2p/peers", handlePeers)

	handleRegister := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var req struct {
			PeerURL string `json:"peer_url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		p := strings.TrimSpace(req.PeerURL)
		if isSafePublicPeer(p) {
			engine.mu.Lock()
			exists := false
			for _, ex := range engine.state.Peers {
				if ex == p {
					exists = true
					break
				}
			}
			if !exists && len(engine.state.Peers) < 64 {
				engine.state.Peers = append(engine.state.Peers, p)
				engine.saveToDisk()
			}
			engine.mu.Unlock()
		}
		writeJSON(w, map[string]interface{}{"status": "ok", "registered": p}, 200)
	}
	mux.HandleFunc("/api/p2p/register", handleRegister)
	mux.HandleFunc("/p2p/register", handleRegister)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Println("\033[38;2;248;250;252m┌──────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[38;2;248;250;252m│ WINEX CORE // AUTONOMOUS LAYER-1 FULL NODE & P2P VALIDATOR ENGINE     v3.6.0 │\033[0m")
	fmt.Println("\033[38;2;248;250;252m├──────────────────────────┬───────────────────────────────────────────────────┤\033[0m")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mNODE ROLE\033[0m                \033[38;2;248;250;252m│\033[0m Sovereign Consensus Validator & Mesh Relay        \033[38;2;248;250;252m│\033[0m\n")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mLOCAL RPC ENDPOINT\033[0m       \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", "http://"+addr)
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mGLOBAL CANONICAL SEED\033[0m    \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", "https://winexcoin.com (Cloudflare Protected)")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mOFFICIAL SUPPORT\033[0m         \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", "support@winexcoin.com")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mLEDGER STATE STORAGE\033[0m     \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", truncateStr(dataPath, 49))
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mCONSENSUS & SUBSIDY\033[0m      \033[38;2;248;250;252m│\033[0m Dual-Pass SHA-256 PoW // 40.0000 WNX (10M Pool)   \033[38;2;248;250;252m│\033[0m\n")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mHALVING SCHEDULE\033[0m         \033[38;2;248;250;252m│\033[0m 125,000 Blocks // 0.0000 WNX Transfer Fee         \033[38;2;248;250;252m│\033[0m\n")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mMAX REORG DEPTH\033[0m          \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", fmt.Sprintf("%d Blocks (Anti-51%% Security Barrier)", MaxReorgDepth))
	fmt.Println("\033[38;2;248;250;252m└──────────────────────────┴───────────────────────────────────────────────────┘\033[0m")
	fmt.Println(" \033[38;2;156;163;175m[LEGAL]\033[0m Non-custodial open-source PoW software - Not a financial/forex product")
	fmt.Println(" \033[38;2;239;68;68m[NOTICE]\033[0m Zero affiliation with unauthorized entities (e.g. 'Winex Markets' forex)")
	fmt.Println(" \033[38;2;16;185;129m[ONLINE]\033[0m Active L1 node synchronized with global peer mesh. Keep terminal open.")

	server := &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	if err := server.ListenAndServe(); err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			fmt.Println(" [INFO] A WINEX Node is already running on " + addr)
			fmt.Println(" [ONLINE] Node connected to existing local daemon. Keep terminal open.")
			select {}
		}
		fmt.Println(" [ERROR] Node listener terminated:", err)
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-(maxLen-3):]
}
