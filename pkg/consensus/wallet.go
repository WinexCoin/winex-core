package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// KeyEntry represents a managed account within the node wallet
type KeyEntry struct {
	Address   string `json:"address"`
	PrivHex   string `json:"private_key"`
	PubHex    string `json:"public_key"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
}

// NodeWallet manages keys for exchange RPC integration
type NodeWallet struct {
	mu       sync.RWMutex
	filePath string
	keys     map[string]*KeyEntry // address -> KeyEntry
}

// NewNodeWallet loads or creates a node wallet file
func NewNodeWallet(walletPath string) (*NodeWallet, error) {
	w := &NodeWallet{
		filePath: walletPath,
		keys:     make(map[string]*KeyEntry),
	}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *NodeWallet) load() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := os.Stat(w.filePath); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(w.filePath)
	if err != nil {
		return err
	}
	var entries []*KeyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	for _, k := range entries {
		w.keys[k.Address] = k
	}
	return nil
}

func (w *NodeWallet) saveLocked() error {
	var entries []*KeyEntry
	for _, k := range w.keys {
		entries = append(entries, k)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(w.filePath)
	_ = os.MkdirAll(dir, 0700)
	tmpPath := fmt.Sprintf("%s.tmp.%d", w.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, w.filePath)
}

// GenerateNewAddress creates a new SECP256k1 keypair and returns address
func (w *NodeWallet) GenerateNewAddress(label string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	privBytes := privKey.Serialize()
	pubBytes := privKey.PubKey().SerializeUncompressed()[1:] // 64 bytes without 0x04

	h := sha256.Sum256(pubBytes)
	address := "WNX" + strings.ToUpper(hex.EncodeToString(h[:16]))

	entry := &KeyEntry{
		Address:   address,
		PrivHex:   hex.EncodeToString(privBytes),
		PubHex:    hex.EncodeToString(pubBytes),
		Label:     label,
		CreatedAt: time.Now().Unix(),
	}
	w.keys[address] = entry
	if err := w.saveLocked(); err != nil {
		delete(w.keys, address)
		return "", err
	}
	return address, nil
}

// GetAddresses returns all wallet addresses
func (w *NodeWallet) GetAddresses() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var addrs []string
	for a := range w.keys {
		addrs = append(addrs, a)
	}
	return addrs
}

// HasAddress checks if an address belongs to this wallet
func (w *NodeWallet) HasAddress(addr string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.keys[addr]
	return ok
}

// GetKeyEntry returns the KeyEntry for an address if owned
func (w *NodeWallet) GetKeyEntry(addr string) (*KeyEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	k, ok := w.keys[addr]
	return k, ok
}

// SignCanonicalTransaction signs a transaction message with the specified key
func (w *NodeWallet) SignCanonicalTransaction(addr, message string) (string, string, error) {
	w.mu.RLock()
	k, ok := w.keys[addr]
	w.mu.RUnlock()
	if !ok {
		return "", "", errors.New("private key for address not found in wallet")
	}

	privBytes, err := hex.DecodeString(k.PrivHex)
	if err != nil {
		return "", "", err
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	h := sha256.Sum256([]byte(message))
	sig := btcecdsa.Sign(privKey, h[:])
	rScalar := sig.R()
	sScalar := sig.S()
	rBytes := rScalar.Bytes()
	sBytes := sScalar.Bytes()
	var sigBuf [64]byte
	copy(sigBuf[0:32], rBytes[:])
	copy(sigBuf[32:64], sBytes[:])

	return hex.EncodeToString(sigBuf[:]), k.PubHex, nil
}
