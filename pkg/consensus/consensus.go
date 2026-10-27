package consensus

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const (
	ChainID           = "WINEX-MAINNET-1"
	CoinName          = "WINEX"
	CoinSymbol        = "WNX"
	SatoshiPerCoin    = int64(100000000) // 1 WNX = 1e8 Satoshis
	GenesisVaultAddr  = "WNX5B15097CB2203643C472AB992FA9FB1A"
	GenesisSupplySat  = int64(2100000) * SatoshiPerCoin  // 2.1M WNX Premine (in satoshis)
	InitialPoolSat    = int64(10000000) * SatoshiPerCoin // 10.0M WNX Mineable Pool (in satoshis)
	InitialRewardSat  = int64(40) * SatoshiPerCoin       // 40.0 WNX Initial Reward (in satoshis)
	HalvingInterval   = int64(125000)
	DefaultDifficulty = 6
	GenesisHash       = "00003789c9e082b2310f3212f4af4aa6daded8d3e8861285ea6c74fd37cfd1a4"
	MaxReorgDepth     = 10
	TargetBlockTime   = 900 // 15 minutes (in seconds)
)

var addrRegex = regexp.MustCompile(`^WNX[0-9A-F]{32}$`)

// ValidateAddress performs strict format verification
func ValidateAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if len(addr) != 35 {
		return false
	}
	return addrRegex.MatchString(addr)
}

// Transaction represents a strictly typed WINEX transaction in Satoshis
type Transaction struct {
	TxID      string `json:"tx_id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	AmountSat int64  `json:"amount_sat"`
	FeeSat    int64  `json:"fee_sat"`
	Nonce     int64  `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

// CanonicalTxPayload builds the deterministic signing string
func CanonicalTxPayload(chainID, sender, recipient string, amountSat, feeSat, nonce, timestamp int64) string {
	return fmt.Sprintf("WINEX-TX-v1|%s|%s|%s|%d|%d|%d|%d", chainID, sender, recipient, amountSat, feeSat, nonce, timestamp)
}

// ComputeTxID calculates the immutable hash from non-malleable payload
func ComputeTxID(chainID, sender, recipient string, amountSat, feeSat, nonce, timestamp int64) string {
	raw := CanonicalTxPayload(chainID, sender, recipient, amountSat, feeSat, nonce, timestamp)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Block represents a canonical block containing transactions
type Block struct {
	Index      int64         `json:"block_index"`
	PrevHash   string        `json:"prev_hash"`
	MerkleRoot string        `json:"merkle_root"`
	Miner      string        `json:"miner"`
	Difficulty int           `json:"difficulty"`
	Nonce      int64         `json:"nonce"`
	Timestamp  float64       `json:"timestamp"`
	Hash       string        `json:"hash"`
	RewardSat  int64         `json:"reward_sat"`
	TxCount    int           `json:"tx_count"`
	Txs        []Transaction `json:"txs,omitempty"`
}

// ComputeMerkleRoot calculates SHA-256 Merkle root from transactions
func ComputeMerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		h := sha256.Sum256([]byte("empty_winex_block"))
		return hex.EncodeToString(h[:])
	}
	hashes := make([][]byte, len(txs))
	for i, tx := range txs {
		b, _ := hex.DecodeString(tx.TxID)
		if len(b) != 32 {
			hb := sha256.Sum256([]byte(tx.TxID))
			b = hb[:]
		}
		hashes[i] = b
	}

	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		nextLevel := make([][]byte, 0, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			comb := append(hashes[i], hashes[i+1]...)
			h := sha256.Sum256(comb)
			nextLevel = append(nextLevel, h[:])
		}
		hashes = nextLevel
	}
	return hex.EncodeToString(hashes[0])
}

// GetBlockRewardSat returns the exact block subsidy in Satoshis for a given height
func GetBlockRewardSat(height int64) int64 {
	if height <= 0 {
		return 0
	}
	eras := (height - 1) / HalvingInterval
	if eras >= 64 {
		return 0
	}
	reward := InitialRewardSat >> uint(eras)
	return reward
}

// ComputePowHash matches the canonical WINEX dual-pass salted hashing algorithm
func ComputePowHash(index int64, prevHash, merkle, minerAddr string, timestamp float64, nonce int64) string {
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

// VerifyTransactionSignature verifies Low-S signature and deterministic payload
func VerifyTransactionSignature(tx *Transaction) error {
	pubBytes, err := hex.DecodeString(strings.TrimSpace(tx.PublicKey))
	if err != nil || len(pubBytes) != 64 {
		return errors.New("invalid 64-byte public key hex")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(tx.Signature))
	if err != nil || len(sigBytes) != 64 {
		return errors.New("invalid 64-byte signature hex")
	}

	// Address derivation check
	addrHash := sha256.Sum256(pubBytes)
	expectedSender := "WNX" + strings.ToUpper(hex.EncodeToString(addrHash[:16]))
	if expectedSender != tx.Sender {
		return errors.New("public key does not match sender address")
	}

	uncompressed := append([]byte{0x04}, pubBytes...)
	pubKey, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// Enforce Low-S malleability protection
	curveOrder := btcec.S256().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		return errors.New("signature S value is high (malleable signature rejected)")
	}

	// Canonical payload verification
	canonicalMsg := CanonicalTxPayload(ChainID, tx.Sender, tx.Recipient, tx.AmountSat, tx.FeeSat, tx.Nonce, tx.Timestamp)
	h256 := sha256.Sum256([]byte(canonicalMsg))

	if ecdsa.Verify(pubKey.ToECDSA(), h256[:], r, s) {
		return nil
	}

	// Legacy fallback support for pre-v4 migration
	legacyMessages := []string{
		fmt.Sprintf("%s:%s:%.8f:%.8f:%.4f", tx.Sender, tx.Recipient, float64(tx.AmountSat)/float64(SatoshiPerCoin), float64(tx.FeeSat)/float64(SatoshiPerCoin), float64(tx.Timestamp)),
		fmt.Sprintf("%s:%s:%.4f:%.4f:%.4f", tx.Sender, tx.Recipient, float64(tx.AmountSat)/float64(SatoshiPerCoin), float64(tx.FeeSat)/float64(SatoshiPerCoin), float64(tx.Timestamp)),
	}
	for _, msg := range legacyMessages {
		lh := sha256.Sum256([]byte(msg))
		if ecdsa.Verify(pubKey.ToECDSA(), lh[:], r, s) {
			return nil
		}
	}

	return errors.New("cryptographic signature mismatch")
}

// SignMessageDomainProtected signs arbitrary messages with domain separation
func SignMessageDomainProtected(privKey *btcec.PrivateKey, message string) (string, error) {
	domainPayload := fmt.Sprintf("WINEX Signed Message:\n%d\n%s", len(message), message)
	h := sha256.Sum256([]byte(domainPayload))

	sig := btcecdsa.Sign(privKey, h[:])
	rScalar := sig.R()
	sScalar := sig.S()
	rBytes := rScalar.Bytes()
	sBytes := sScalar.Bytes()

	var sigBuf [64]byte
	copy(sigBuf[0:32], rBytes[:])
	copy(sigBuf[32:64], sBytes[:])

	return hex.EncodeToString(sigBuf[:]), nil
}

// VerifyMessageDomainProtected verifies message signature with strict domain separation
func VerifyMessageDomainProtected(pubKeyHex, address, message, sigHex string) error {
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != 64 {
		return errors.New("invalid 64-byte public key hex")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != 64 {
		return errors.New("invalid 64-byte signature hex")
	}

	cleanAddr := strings.TrimSpace(address)
	if cleanAddr != "" {
		h := sha256.Sum256(pubBytes)
		derived := "WNX" + strings.ToUpper(hex.EncodeToString(h[:16]))
		if derived != cleanAddr {
			return fmt.Errorf("public key does not derive address %s (got %s)", cleanAddr, derived)
		}
	}

	uncompressed := append([]byte{0x04}, pubBytes...)
	pubKey, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return fmt.Errorf("failed to parse pubkey: %w", err)
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// Check domain-separated message
	domainPayload := fmt.Sprintf("WINEX Signed Message:\n%d\n%s", len(message), message)
	h256 := sha256.Sum256([]byte(domainPayload))
	if ecdsa.Verify(pubKey.ToECDSA(), h256[:], r, s) {
		return nil
	}

	// Bare sha256 fallback for backwards compatibility
	bare := sha256.Sum256([]byte(message))
	if ecdsa.Verify(pubKey.ToECDSA(), bare[:], r, s) {
		return nil
	}

	return errors.New("signature verification failed")
}
