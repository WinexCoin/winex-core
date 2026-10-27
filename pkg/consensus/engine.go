package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var defaultTargetHex = "000000000c370000000000000000000000000000000000000000000000000000"

// SafeHTTPClient creates an HTTP client with private IP SSRF prevention and redirects disabled
func SafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip != nil && IsPrivateIP(ip) {
				return errors.New("connection to private/loopback/link-local address prohibited (SSRF guard)")
			}
			return nil
		},
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if IsPrivateIP(ip.IP) {
					return nil, fmt.Errorf("SSRF protection: resolved host %s to private IP %s", host, ip.IP.String())
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Deny redirects to prevent open-redirect SSRF bypasses
		},
	}
}

// IsPrivateIP checks if an IP is loopback, RFC1918, link-local, multicast or unspecified
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Check IPv4 mapped IPv6
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) {
			return true
		}
		if ip4[0] == 127 || (ip4[0] == 169 && ip4[1] == 254) || ip4[0] == 0 {
			return true
		}
	}
	return false
}

// IsSafePublicPeer verifies a peer URL before contact
func IsSafePublicPeer(rawURL string) bool {
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
		return !IsPrivateIP(ip)
	}
	// Resolves safely
	ips, err := net.LookupIP(h)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, rip := range ips {
		if IsPrivateIP(rip) {
			return false
		}
	}
	return true
}

// StorageWriter abstraction for injectable persistence and fault testing
type StorageWriter interface {
	WriteAtomic(path string, data []byte) error
}

type defaultStorageWriter struct{}

func (d *defaultStorageWriter) WriteAtomic(path string, data []byte) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// BlockchainState holds persistent ledger and memory state in satoshis
type BlockchainState struct {
	Blocks           []Block          `json:"blocks"`
	BalancesSat      map[string]int64 `json:"balances_sat"`
	PoolRemainingSat int64            `json:"pool_remaining_sat"`
	AccountNonces    map[string]int64 `json:"account_nonces"`
	Mempool          []Transaction    `json:"mempool"`
	SeenSigs         map[string]int64 `json:"seen_sigs"` // sig -> expiration timestamp
	Peers            []string         `json:"peers"`
}

// NodeEngine implements autonomous, zero-trust Layer-1 consensus
type NodeEngine struct {
	mu             sync.RWMutex
	state          BlockchainState
	dataPath       string
	bootstrapNodes []string
	storage        StorageWriter
	targetHex      string
}

// SetStorageWriter allows injecting a mock/fault storage writer for testing
func (n *NodeEngine) SetStorageWriter(sw StorageWriter) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.storage = sw
}

// SetTargetHex allows overriding PoW target for testing and isolated networks
func (n *NodeEngine) SetTargetHex(target string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.targetHex = target
}

func (n *NodeEngine) getTargetHexLocked() string {
	if n.targetHex != "" {
		return n.targetHex
	}
	return defaultTargetHex
}

// NewNodeEngine initializes the node state
func NewNodeEngine(dataPath string, bootstrap []string) *NodeEngine {
	if len(bootstrap) == 0 {
		bootstrap = []string{"https://winexcoin.com"}
	}
	n := &NodeEngine{
		dataPath:       dataPath,
		bootstrapNodes: bootstrap,
		storage:        &defaultStorageWriter{},
		state: BlockchainState{
			Blocks:           []Block{},
			BalancesSat:      make(map[string]int64),
			PoolRemainingSat: InitialPoolSat,
			AccountNonces:    make(map[string]int64),
			Mempool:          []Transaction{},
			SeenSigs:         make(map[string]int64),
			Peers:            []string{},
		},
	}
	n.loadOrInitGenesis()
	return n
}

// ReplayAndVerifyLedger verifies block continuity, PoW, Merkle roots, signatures and recomputes balances from scratch
func (n *NodeEngine) ReplayAndVerifyLedger(blocks []Block) (map[string]int64, int64, map[string]int64, error) {
	if len(blocks) == 0 {
		return nil, 0, nil, errors.New("empty block chain")
	}
	if blocks[0].Hash != GenesisHash || blocks[0].Index != 0 {
		return nil, 0, nil, errors.New("genesis block mismatch")
	}

	computedBalances := make(map[string]int64)
	computedBalances[GenesisVaultAddr] = GenesisSupplySat
	computedPool := InitialPoolSat
	computedNonces := make(map[string]int64)

	for i := 1; i < len(blocks); i++ {
		prev := &blocks[i-1]
		curr := &blocks[i]
		if err := n.ValidateBlock(prev, curr); err != nil {
			return nil, 0, nil, fmt.Errorf("block #%d validation failed: %w", curr.Index, err)
		}

		// Verify TxCount matches actual transactions in block
		if curr.TxCount != len(curr.Txs) {
			return nil, 0, nil, fmt.Errorf("block #%d tx_count mismatch: header %d, actual %d", curr.Index, curr.TxCount, len(curr.Txs))
		}

		// Verify Merkle Root matches transactions in block
		expectedMerkle := ComputeMerkleRoot(curr.Txs)
		if curr.MerkleRoot != expectedMerkle {
			return nil, 0, nil, fmt.Errorf("block #%d merkle root mismatch: header %s, computed %s", curr.Index, curr.MerkleRoot, expectedMerkle)
		}

		// Verify Block Subsidy matches height protocol: strictly non-negative and <= expected
		if curr.RewardSat < 0 {
			return nil, 0, nil, fmt.Errorf("block #%d negative subsidy rejected: %d satoshis", curr.Index, curr.RewardSat)
		}
		expectedSubsidy := GetBlockRewardSat(curr.Index)
		if curr.RewardSat > expectedSubsidy {
			return nil, 0, nil, fmt.Errorf("block #%d subsidy %d exceeds protocol allowed %d", curr.Index, curr.RewardSat, expectedSubsidy)
		}

		reward := curr.RewardSat
		if reward > computedPool {
			reward = computedPool
		}

		var totalBlockFees int64

		// Replay and verify each transaction in block
		for _, tx := range curr.Txs {
			// Arithmetic overflow check on total cost
			if tx.AmountSat <= 0 || tx.AmountSat > MaxSupplySat {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: invalid amount %d", curr.Index, tx.TxID, tx.AmountSat)
			}
			if tx.FeeSat < 0 || tx.FeeSat > 1000*SatoshiPerCoin {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: invalid fee %d", curr.Index, tx.TxID, tx.FeeSat)
			}
			if tx.AmountSat > (math.MaxInt64 - tx.FeeSat) {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: amount+fee overflow", curr.Index, tx.TxID)
			}
			totalCost := tx.AmountSat + tx.FeeSat

			// Verify Canonical TxID matches computed TxID
			computedTxID := ComputeTxID(ChainID, tx.Sender, tx.Recipient, tx.AmountSat, tx.FeeSat, tx.Nonce, tx.Timestamp)
			if tx.TxID != computedTxID {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: TxID mismatch (expected %s)", curr.Index, tx.TxID, computedTxID)
			}

			// Verify cryptographic signature
			if err := VerifyTransactionSignature(&tx); err != nil {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s signature invalid: %w", curr.Index, tx.TxID, err)
			}

			// Verify sender balance
			if computedBalances[tx.Sender] < totalCost {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: insufficient balance for sender %s", curr.Index, tx.TxID, tx.Sender)
			}

			// Nonce ordering check
			if tx.Nonce != 0 && tx.Nonce <= computedNonces[tx.Sender] {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: nonce %d must be > %d", curr.Index, tx.TxID, tx.Nonce, computedNonces[tx.Sender])
			}
			if tx.Nonce > 0 {
				computedNonces[tx.Sender] = tx.Nonce
			}

			// Apply state transition with checked arithmetic
			computedBalances[tx.Sender] -= totalCost
			if computedBalances[tx.Recipient] > (MaxSupplySat - tx.AmountSat) {
				return nil, 0, nil, fmt.Errorf("block #%d transaction %s: recipient balance overflow", curr.Index, tx.TxID)
			}
			computedBalances[tx.Recipient] += tx.AmountSat

			if totalBlockFees > (math.MaxInt64 - tx.FeeSat) {
				return nil, 0, nil, fmt.Errorf("block #%d total fees overflow", curr.Index)
			}
			totalBlockFees += tx.FeeSat
		}

		minerTotalReward := reward + totalBlockFees
		if computedBalances[curr.Miner] > (MaxSupplySat - minerTotalReward) {
			return nil, 0, nil, fmt.Errorf("block #%d miner balance overflow", curr.Index)
		}
		computedBalances[curr.Miner] += minerTotalReward
		if computedPool >= reward {
			computedPool -= reward
		}
	}

	return computedBalances, computedPool, computedNonces, nil
}

// Load genesis or recover existing chain state with cryptographic audit
func (n *NodeEngine) loadOrInitGenesis() {
	_ = os.MkdirAll(filepath.Dir(n.dataPath), 0700)

	if b, err := os.ReadFile(n.dataPath); err == nil {
		var s BlockchainState
		if err := json.Unmarshal(b, &s); err == nil && len(s.Blocks) > 0 {
			// Cryptographically replay and audit the chain before trusting in-memory state
			verifiedBalances, verifiedPool, verifiedNonces, err := n.ReplayAndVerifyLedger(s.Blocks)
			if err != nil {
				// Safely quarantine corrupted state without overwriting existing quarantine files
				quarantinePath := fmt.Sprintf("%s.corrupted.%d", n.dataPath, time.Now().UnixNano())
				fmt.Printf("[SECURITY WARNING] Corrupted chain in %s (%v). Quarantining to %s and initializing clean genesis.\n", n.dataPath, err, quarantinePath)
				_ = os.Rename(n.dataPath, quarantinePath)
			} else {
				n.state = s
				n.state.BalancesSat = verifiedBalances
				n.state.PoolRemainingSat = verifiedPool
				n.state.AccountNonces = verifiedNonces
				if n.state.SeenSigs == nil {
					n.state.SeenSigs = make(map[string]int64)
				}
				return
			}
		}
	}

	genesis := Block{
		Index:      0,
		PrevHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		MerkleRoot: "0000000000000000000000000000000000000000000000000000000000000000",
		Miner:      GenesisVaultAddr,
		Difficulty: DefaultDifficulty,
		Nonce:      0,
		Timestamp:  1740000000.0,
		Hash:       GenesisHash,
		RewardSat:  GenesisSupplySat,
		TxCount:    0,
	}

	n.state.Blocks = []Block{genesis}
	n.state.BalancesSat = make(map[string]int64)
	n.state.BalancesSat[GenesisVaultAddr] = GenesisSupplySat
	n.state.PoolRemainingSat = InitialPoolSat
	n.state.AccountNonces = make(map[string]int64)
	n.state.SeenSigs = make(map[string]int64)
	_ = n.saveToDiskAtomic()
}

// cloneStateLocked returns a deep copy of the in-memory BlockchainState
func (n *NodeEngine) cloneStateLocked() BlockchainState {
	st := BlockchainState{
		Blocks:           make([]Block, len(n.state.Blocks)),
		BalancesSat:      make(map[string]int64, len(n.state.BalancesSat)),
		PoolRemainingSat: n.state.PoolRemainingSat,
		AccountNonces:    make(map[string]int64, len(n.state.AccountNonces)),
		Mempool:          make([]Transaction, len(n.state.Mempool)),
		SeenSigs:         make(map[string]int64, len(n.state.SeenSigs)),
		Peers:            make([]string, len(n.state.Peers)),
	}
	copy(st.Blocks, n.state.Blocks)
	for k, v := range n.state.BalancesSat {
		st.BalancesSat[k] = v
	}
	for k, v := range n.state.AccountNonces {
		st.AccountNonces[k] = v
	}
	copy(st.Mempool, n.state.Mempool)
	for k, v := range n.state.SeenSigs {
		st.SeenSigs[k] = v
	}
	copy(st.Peers, n.state.Peers)
	return st
}

// saveStateToDiskAtomic persists the provided state atomically to disk
func (n *NodeEngine) saveStateToDiskAtomic(state *BlockchainState) error {
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if n.storage != nil {
		return n.storage.WriteAtomic(n.dataPath, b)
	}
	d := &defaultStorageWriter{}
	return d.WriteAtomic(n.dataPath, b)
}

// Atomic file write using storage abstraction
func (n *NodeEngine) saveToDiskAtomic() error {
	return n.saveStateToDiskAtomic(&n.state)
}

// GetPendingReservedBalanceLocked returns total satoshis currently locked in mempool for sender
func (n *NodeEngine) GetPendingReservedBalanceLocked(sender string) int64 {
	var reserved int64
	for _, tx := range n.state.Mempool {
		if tx.Sender == sender {
			reserved += (tx.AmountSat + tx.FeeSat)
		}
	}
	return reserved
}

// GetBalanceLocked returns confirmed balance from local ledger without locking
func (n *NodeEngine) GetBalanceLocked(addr string) int64 {
	return n.state.BalancesSat[addr]
}

// GetSpendableBalanceLocked calculates confirmed balance minus pending mempool outgoing
func (n *NodeEngine) GetSpendableBalanceLocked(addr string) int64 {
	confirmed := n.state.BalancesSat[addr]
	reserved := n.GetPendingReservedBalanceLocked(addr)
	spendable := confirmed - reserved
	if spendable < 0 {
		return 0
	}
	return spendable
}

// GetBalance returns address balance computed strictly from verified local chain
func (n *NodeEngine) GetBalance(addr string) map[string]interface{} {
	addr = strings.TrimSpace(addr)
	n.mu.RLock()
	defer n.mu.RUnlock()
	balSat := n.state.BalancesSat[addr]
	balCoins := float64(balSat) / float64(SatoshiPerCoin)
	return map[string]interface{}{
		"address":      addr,
		"balance":      balCoins,
		"balance_sat":  balSat,
		"block_height": len(n.state.Blocks),
	}
}

// GetStatus returns the current consensus state
func (n *NodeEngine) GetStatus() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()

	height := int64(len(n.state.Blocks))
	latestHash := GenesisHash
	if height > 0 {
		latestHash = n.state.Blocks[height-1].Hash
	}
	poolRemCoins := float64(n.state.PoolRemainingSat) / float64(SatoshiPerCoin)
	rewardSat := GetBlockRewardSat(height)
	if rewardSat <= 0 {
		rewardSat = InitialRewardSat
	}
	rewardCoins := float64(rewardSat) / float64(SatoshiPerCoin)

	return map[string]interface{}{
		"chain_id":               ChainID,
		"coin_name":              CoinName,
		"symbol":                 CoinSymbol,
		"status":                 "online",
		"node":                   "WINEX Sovereign Standalone L1 Node (Hardened v4)",
		"block_height":           height,
		"latest_hash":            latestHash,
		"difficulty":             DefaultDifficulty,
		"difficulty_target":      defaultTargetHex,
		"difficulty_multiplier":  1.0,
		"block_reward":           rewardCoins,
		"block_reward_sat":       rewardSat,
		"mining_pool_available":  poolRemCoins,
		"pool_remaining":         poolRemCoins,
		"mempool_tx_count":       len(n.state.Mempool),
		"peer_count":             len(n.state.Peers),
		"timestamp":              time.Now().Unix(),
	}
}

// GetMiningTemplate constructs template strictly from local state
func (n *NodeEngine) GetMiningTemplate() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()

	idx := int64(len(n.state.Blocks))
	prev := GenesisHash
	if idx > 0 {
		prev = n.state.Blocks[idx-1].Hash
	}

	merkle := ComputeMerkleRoot(n.state.Mempool)
	rewardSat := GetBlockRewardSat(idx)
	if rewardSat > n.state.PoolRemainingSat {
		rewardSat = n.state.PoolRemainingSat
	}
	rewardCoins := float64(rewardSat) / float64(SatoshiPerCoin)
	poolRemCoins := float64(n.state.PoolRemainingSat) / float64(SatoshiPerCoin)

	return map[string]interface{}{
		"block_index":           idx,
		"prev_hash":             prev,
		"merkle_root":           merkle,
		"difficulty":            DefaultDifficulty,
		"target":                defaultTargetHex,
		"target_prefix":         "000000",
		"difficulty_multiplier": 1.0,
		"reward":                rewardCoins,
		"reward_sat":            rewardSat,
		"pool_remaining":        poolRemCoins,
		"tx_count":              len(n.state.Mempool),
	}
}

// ValidateBlock performs full independent consensus verification on a candidate block
func (n *NodeEngine) ValidateBlock(prev *Block, blk *Block) error {
	if prev != nil {
		if blk.Index != prev.Index+1 {
			return fmt.Errorf("index discontinuity: expected %d, got %d", prev.Index+1, blk.Index)
		}
		if blk.PrevHash != prev.Hash {
			return fmt.Errorf("prev_hash mismatch: expected %s, got %s", prev.Hash, blk.PrevHash)
		}
		if blk.Timestamp < prev.Timestamp-60.0 {
			return errors.New("block timestamp older than parent block (monotonic violation)")
		}
	} else if blk.Index != 0 {
		return errors.New("cannot validate non-genesis block without parent")
	}

	now := float64(time.Now().Unix())
	if blk.Timestamp > now+7200.0 {
		return errors.New("block timestamp is more than 2 hours in future drift")
	}

	// Verify PoW hash meets difficulty
	computedHash := ComputePowHash(blk.Index, blk.PrevHash, blk.MerkleRoot, blk.Miner, blk.Timestamp, blk.Nonce)
	if computedHash != blk.Hash {
		return fmt.Errorf("computed hash %s does not match block hash %s", computedHash, blk.Hash)
	}

	// Target check with big.Int
	targetHex := n.getTargetHexLocked()
	targetInt, _ := new(big.Int).SetString(targetHex, 16)
	hashInt, _ := new(big.Int).SetString(computedHash, 16)
	if hashInt.Cmp(targetInt) >= 0 {
		return errors.New("block hash exceeds numerical target")
	}

	return nil
}

// SubmitBlock validates and commits a new block locally and broadcasts it
func (n *NodeEngine) SubmitBlock(minerAddr string, index, nonce int64, ts float64, submittedHash string) (bool, string) {
	if !ValidateAddress(minerAddr) {
		return false, "Invalid miner address format (35 characters WNX expected)"
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	curHeight := int64(len(n.state.Blocks))
	if index != curHeight {
		return false, fmt.Sprintf("Stale or invalid block index: expected %d, got %d", curHeight, index)
	}

	var prev *Block
	if curHeight > 0 {
		prev = &n.state.Blocks[curHeight-1]
	}

	merkle := ComputeMerkleRoot(n.state.Mempool)
	rewardSat := GetBlockRewardSat(index)
	if rewardSat > n.state.PoolRemainingSat {
		rewardSat = n.state.PoolRemainingSat
	}

	blk := Block{
		Index:      index,
		PrevHash:   prev.Hash,
		MerkleRoot: merkle,
		Miner:      minerAddr,
		Difficulty: DefaultDifficulty,
		Nonce:      nonce,
		Timestamp:  ts,
		Hash:       submittedHash,
		RewardSat:  rewardSat,
		TxCount:    len(n.state.Mempool),
		Txs:        make([]Transaction, len(n.state.Mempool)),
	}
	copy(blk.Txs, n.state.Mempool)

	if err := n.ValidateBlock(prev, &blk); err != nil {
		return false, fmt.Sprintf("Consensus rejection: %v", err)
	}

	// Calculate and assign total fees from mempool transactions to miner
	var totalFeesSat int64
	for _, tx := range blk.Txs {
		totalFeesSat += tx.FeeSat
	}

	// Atomic Staged Commit: clone state, apply mutations to staged copy
	staged := n.cloneStateLocked()

	// Apply confirmed transaction settlement now that block is committed
	for _, tx := range blk.Txs {
		staged.BalancesSat[tx.Sender] -= (tx.AmountSat + tx.FeeSat)
		staged.BalancesSat[tx.Recipient] += tx.AmountSat
	}

	staged.Blocks = append(staged.Blocks, blk)
	staged.BalancesSat[minerAddr] += (rewardSat + totalFeesSat)
	if staged.PoolRemainingSat >= rewardSat {
		staged.PoolRemainingSat -= rewardSat
	}
	staged.Mempool = []Transaction{}

	if err := n.saveStateToDiskAtomic(&staged); err != nil {
		return false, fmt.Sprintf("Persistence failure committing block: %v", err)
	}

	n.state = staged
	return true, fmt.Sprintf("Block #%d committed with %d txs and %d satoshis reward", index, len(blk.Txs), rewardSat+totalFeesSat)
}

// AddTransaction executes full validation without re-entrant deadlock
func (n *NodeEngine) AddTransaction(sender, recip string, amountSat, feeSat, nonce, ts int64, pubKey, sig string) (bool, string) {
	if !ValidateAddress(sender) || !ValidateAddress(recip) {
		return false, "Invalid WNX address format (must match ^WNX[0-9A-F]{32}$)"
	}
	if sender == recip {
		return false, "Self-transfers are prohibited"
	}
	// Strict overflow and bounds checks for amount and fee
	if amountSat <= 0 || amountSat > MaxSupplySat {
		return false, "Invalid transfer amount: out of protocol bounds (must be > 0 and <= MaxSupply)"
	}
	if feeSat < 0 || feeSat > 1000*SatoshiPerCoin {
		return false, "Invalid fee parameter: out of protocol bounds"
	}

	// Arithmetic overflow check on totalReqSat = amountSat + feeSat
	if amountSat > (math.MaxInt64 - feeSat) {
		return false, "Integer overflow detected in transfer calculation"
	}
	totalReqSat := amountSat + feeSat

	now := time.Now().Unix()
	if ts < now-86400 || ts > now+7200 {
		return false, "Transaction timestamp drift out of bounds"
	}

	tx := Transaction{
		Sender:    sender,
		Recipient: recip,
		AmountSat: amountSat,
		FeeSat:    feeSat,
		Nonce:     nonce,
		Timestamp: ts,
		PublicKey: pubKey,
		Signature: sig,
	}
	tx.TxID = ComputeTxID(ChainID, sender, recip, amountSat, feeSat, nonce, ts)

	if err := VerifyTransactionSignature(&tx); err != nil {
		return false, fmt.Sprintf("Cryptographic signature failure: %v", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Memory pool limits
	if len(n.state.Mempool) >= 10000 {
		return false, "Mempool congestion: maximum pending capacity reached (10,000 txs)"
	}

	// Replay protection with Low-S and expiration
	if exp, exists := n.state.SeenSigs[sig]; exists && exp > now {
		return false, "Replay attack rejected: duplicate signature seen in active window"
	}

	// Nonce order check
	expectedNonce := n.state.AccountNonces[sender] + 1
	if nonce != 0 && nonce < expectedNonce {
		return false, fmt.Sprintf("Nonce too low: expected %d, got %d", expectedNonce, nonce)
	}

	// Spendable balance check: Confirmed balance minus all pending mempool transactions from sender
	spendableBalSat := n.GetSpendableBalanceLocked(sender)
	if spendableBalSat < totalReqSat {
		return false, fmt.Sprintf("Insufficient spendable balance: available %d satoshis, required %d satoshis (pending locked: %d)",
			spendableBalSat, totalReqSat, n.GetPendingReservedBalanceLocked(sender))
	}

	// Recipient balance overflow check against confirmed balance
	confirmedRecipBalSat := n.state.BalancesSat[recip]
	if confirmedRecipBalSat > (MaxSupplySat - amountSat) {
		return false, "Recipient balance overflow: cannot exceed maximum supply"
	}

	// Atomic staged commit: clone state, update staged copy, persist, and swap
	staged := n.cloneStateLocked()
	if nonce >= expectedNonce {
		staged.AccountNonces[sender] = nonce
	}
	staged.SeenSigs[sig] = now + 86400 // Store for 24h window
	staged.Mempool = append(staged.Mempool, tx)

	if err := n.saveStateToDiskAtomic(&staged); err != nil {
		return false, fmt.Sprintf("State persistence failure: %v", err)
	}

	n.state = staged
	return true, tx.TxID
}

// WriteJSON helper for HTTP responses
func WriteJSON(w http.ResponseWriter, data interface{}, code int) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(data)
}

// AddPeerSafely checks limits and registers verified peers
func (n *NodeEngine) AddPeerSafely(peerURL string) bool {
	peerURL = strings.TrimSpace(peerURL)
	if peerURL == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.state.Peers {
		if p == peerURL {
			return false
		}
	}
	if len(n.state.Peers) >= 64 {
		return false
	}
	n.state.Peers = append(n.state.Peers, peerURL)
	_ = n.saveToDiskAtomic()
	return true
}
func (n *NodeEngine) GetBlocks(limit int) []Block {
	n.mu.RLock()
	defer n.mu.RUnlock()

	total := len(n.state.Blocks)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if limit > total {
		limit = total
	}
	blks := make([]Block, 0, limit)
	for i := total - 1; i >= total-limit; i-- {
		blks = append(blks, n.state.Blocks[i])
	}
	return blks
}
