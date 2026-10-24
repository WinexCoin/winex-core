package main

import (
	"bytes"
	"crypto/aes"
	_ "embed"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/skip2/go-qrcode"
	"github.com/tyler-smith/go-bip39"
	"winex-wallet/nodecore"
	"golang.org/x/crypto/pbkdf2"
)

//go:embed assets/winex_wallet_gui.py
var embeddedPyQtGUI []byte

//go:embed assets/winex_core.py
var embeddedWinexCore []byte

//go:embed assets/winex_logo.png
var embeddedLogoPng []byte

//go:embed assets/favicon.ico
var embeddedFaviconIco []byte


const defaultRemoteNode = "https://winexcoin.com"

type EncryptedVault struct {
	Version   int    `json:"version"`
	SaltHex   string `json:"salt"`
	NonceHex  string `json:"nonce"`
	CipherHex string `json:"ciphertext"`
}

type HDAccount struct {
	Index      int     `json:"index"`
	Label      string  `json:"label"`
	PrivateKey string  `json:"private_key"`
	PublicKey  string  `json:"public_key"`
	Address    string  `json:"address"`
	Derivation string  `json:"derivation"`
	Balance    float64 `json:"balance"`
	IsActive   bool    `json:"is_active,omitempty"`
}

type WalletData struct {
	SeedPhrase string      `json:"seed_phrase"`
	PrivateKey string      `json:"private_key"`
	PublicKey  string      `json:"public_key"`
	Address    string      `json:"address"`
	NodeURL    string      `json:"node_url"`
	Accounts   []HDAccount `json:"accounts,omitempty"`
}

type MiningState struct {
	Active       bool   `json:"active"`
	HashRate     string `json:"hash_rate"`
	TotalHashes  int64  `json:"total_hashes"`
	BlocksMined  int64  `json:"blocks_mined"`
	Threads      int    `json:"threads"`
	ActiveTarget string `json:"active_target"`
}

var (
	vaultLock   sync.Mutex
	activeVault *WalletData
	activePw    string

	minerLock  sync.Mutex
	minerState MiningState
	stopMiner  chan struct{}
	csrfToken  string
)

func initCSRFToken() {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	csrfToken = hex.EncodeToString(b)
}

func getWalletDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".winex")
}

func getVaultPath() string {
	return filepath.Join(getWalletDir(), "vault.v3.json")
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	p := unsafe.StringData(*s)
	b := unsafe.Slice(p, len(*s))
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

func purgeSensitiveMemoryLocked() {
	if activeVault != nil {
		zeroString(&activeVault.SeedPhrase)
		zeroString(&activeVault.PrivateKey)
		for i := range activeVault.Accounts {
			zeroString(&activeVault.Accounts[i].PrivateKey)
		}
		activeVault = nil
	}
	zeroString(&activePw)
	runtime.GC()
	debug.FreeOSMemory()
}

func syncMinerAddressFile(addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	_ = os.MkdirAll(getWalletDir(), 0700)
	_ = os.WriteFile(filepath.Join(getWalletDir(), "miner_address.txt"), []byte(strings.TrimSpace(addr)), 0600)
}

func purgeLegacyVaults() {
	dir := getWalletDir()
	_ = os.Remove(filepath.Join(dir, "vault.json"))
	_ = os.Remove(filepath.Join(dir, "vault.v2.json"))
}

func hasExistingVault() bool {
	_, err := os.Stat(getVaultPath())
	return err == nil
}

// ==================== BACKGROUND NODE AUTO-STARTER ====================

func isLocalNodeHealthy() bool {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get("http://127.0.0.1:8081/stats")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// ensureBackgroundNodeRunning starts the full WINEX node INSIDE this wallet process.
// No separate WINEX_Node process is spawned: when the wallet exits, the node stops with it.
func ensureBackgroundNodeRunning() string {
	if isLocalNodeHealthy() {
		return "EXTERNAL_NODE_ACTIVE (:8081)"
	}
	go nodecore.Run("127.0.0.1", 8081)
	for i := 0; i < 40; i++ {
		time.Sleep(100 * time.Millisecond)
		if isLocalNodeHealthy() {
			return "EMBEDDED_NODE_ACTIVE (:8081)"
		}
	}
	return "EMBEDDED_NODE_STARTING (:8081)"
}

func startEmbeddedFallbackNode() {
	go func() {
		var mu sync.RWMutex
		cachedHeight := int64(0)
		cachedSupply := 0.0
		cachedReward := 40.0
		cachedPool := 10000000.0
		cachedTarget := "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		var syncedBlocks interface{} = []interface{}{}

		syncLoop := func() {
			client := &http.Client{Timeout: 5 * time.Second}
			for {
				resp, err := client.Get(defaultRemoteNode + "/api/state")
				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var st map[string]interface{}
					if json.Unmarshal(body, &st) == nil {
						mu.Lock()
						if v, ok := st["block_height"].(float64); ok {
							cachedHeight = int64(v)
						}
						if v, ok := st["total_supply"].(float64); ok {
							cachedSupply = v
						}
						if v, ok := st["block_reward"].(float64); ok {
							cachedReward = v
						}
						if v, ok := st["pool_remaining"].(float64); ok {
							cachedPool = v
						}
						if v, ok := st["difficulty_target"].(string); ok && v != "" {
							cachedTarget = v
						}
						mu.Unlock()
					}
				}
				respC, errC := client.Get(defaultRemoteNode + "/api/chain?limit=50")
				if errC == nil {
					bodyC, _ := io.ReadAll(respC.Body)
					respC.Body.Close()
					var ch map[string]interface{}
					if json.Unmarshal(bodyC, &ch) == nil {
						mu.Lock()
						if b, ok := ch["blocks"]; ok {
							syncedBlocks = b
						}
						mu.Unlock()
					}
				}
				time.Sleep(8 * time.Second)
			}
		}
		go syncLoop()

		mux := http.NewServeMux()

	mux.HandleFunc("/winex_logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(embeddedLogoPng)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(embeddedFaviconIco)
	})
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			mu.RLock()
			defer mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"network":           "WINEX Mainnet",
				"height":            cachedHeight,
				"total_supply":      cachedSupply,
				"max_supply":        10000000.0,
				"block_reward":      cachedReward,
				"pool_remaining":    cachedPool,
				"difficulty_target": cachedTarget,
				"seed_node":         defaultRemoteNode,
				"status":            "SYNCHRONIZED",
			})
		})
		mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) {
			mu.RLock()
			defer mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"height": cachedHeight,
				"blocks": syncedBlocks,
			})
		})
		_ = http.ListenAndServe("127.0.0.1:8081", mux)
	}()
}

// ==================== CRYPTOGRAPHY & VAULT ====================

func generateNewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func deriveHDAccount(mnemonic string, index int, label string) HDAccount {
	cleanSeed := strings.TrimSpace(mnemonic)
	seedBytes := bip39.NewSeed(cleanSeed, "")

	var h512 [32]byte
	if index == 0 {
		h512 = sha256.Sum256(seedBytes)
	} else {
		suffix := fmt.Sprintf(":WINEX_HD_ACCOUNT:%d", index)
		buf := append(append([]byte{}, seedBytes...), []byte(suffix)...)
		h512 = sha256.Sum256(buf)
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(h512[:])
	privBytes := privKey.Serialize()
	pubX := pubKey.X().Bytes()
	pubY := pubKey.Y().Bytes()

	var rawPub [64]byte
	copy(rawPub[32-len(pubX):32], pubX)
	copy(rawPub[64-len(pubY):64], pubY)

	pubHex := hex.EncodeToString(rawPub[:])
	h := sha256.Sum256(rawPub[:])
	addr := "WNX" + strings.ToUpper(hex.EncodeToString(h[:16]))
	if label == "" {
		if index == 0 {
			label = "Primary Account"
		} else {
			label = fmt.Sprintf("Account #%d", index)
		}
	}
	return HDAccount{
		Index:      index,
		Label:      label,
		PrivateKey: hex.EncodeToString(privBytes[:]),
		PublicKey:  pubHex,
		Address:    addr,
		Derivation: fmt.Sprintf("m/44'/999'/0'/0/%d", index),
	}
}

func discoverHDAccounts(mnemonic, nodeURL string) []HDAccount {
	cleanSeed := strings.TrimSpace(mnemonic)
	acc0 := deriveHDAccount(cleanSeed, 0, "Primary Account")
	accounts := []HDAccount{acc0}
	if nodeURL == "" {
		nodeURL = defaultRemoteNode
	}

	client := &http.Client{Timeout: 1800 * time.Millisecond}

	// Scan gap limit: check indices 1..20 for any balance or history
	highestActive := 0
	type scannedAcc struct {
		acc HDAccount
		bal float64
	}
	var scanned []scannedAcc

	for i := 1; i <= 20; i++ {
		candidate := deriveHDAccount(cleanSeed, i, fmt.Sprintf("Account #%d", i))
		var bVal float64 = 0.0
		resp, err := client.Get(fmt.Sprintf("%s/api/balance/%s", nodeURL, candidate.Address))
		if err == nil {
			var bMap map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&bMap); err == nil {
				if v, ok := bMap["balance"].(float64); ok {
					bVal = v
				}
			}
			resp.Body.Close()
		}
		candidate.Balance = bVal
		if bVal > 0 {
			highestActive = i
		}
		scanned = append(scanned, scannedAcc{acc: candidate, bal: bVal})
	}

	for i := 0; i < highestActive; i++ {
		accounts = append(accounts, scanned[i].acc)
	}

	return accounts
}

func deriveWalletFromMnemonic(mnemonic, nodeURL string) WalletData {
	cleanSeed := strings.TrimSpace(mnemonic)
	if nodeURL == "" {
		nodeURL = defaultRemoteNode
	}
	accounts := discoverHDAccounts(cleanSeed, nodeURL)
	acc0 := accounts[0]

	return WalletData{
		SeedPhrase: cleanSeed,
		PrivateKey: acc0.PrivateKey,
		PublicKey:  acc0.PublicKey,
		Address:    acc0.Address,
		NodeURL:    nodeURL,
		Accounts:   accounts,
	}
}

func encryptVault(w WalletData, password string) (*EncryptedVault, error) {
	plainBytes, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherBytes := gcm.Seal(nil, nonce, plainBytes, nil)

	return &EncryptedVault{
		Version:   3,
		SaltHex:   hex.EncodeToString(salt),
		NonceHex:  hex.EncodeToString(nonce),
		CipherHex: hex.EncodeToString(cipherBytes),
	}, nil
}

func decryptVault(ev *EncryptedVault, password string) (*WalletData, error) {
	if ev.Version != 3 {
		return nil, fmt.Errorf("Unsupported vault version")
	}
	salt, err := hex.DecodeString(ev.SaltHex)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(ev.NonceHex)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := hex.DecodeString(ev.CipherHex)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainBytes, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("Invalid password or corrupted vault file")
	}
	defer zeroBytes(plainBytes)

	var w WalletData
	if err := json.Unmarshal(plainBytes, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func saveVaultToDisk(ev *EncryptedVault) error {
	_ = os.MkdirAll(getWalletDir(), 0700)
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getVaultPath(), b, 0600)
}

func loadVaultFromDisk() (*EncryptedVault, error) {
	b, err := os.ReadFile(getVaultPath())
	if err != nil {
		return nil, err
	}
	var ev EncryptedVault
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func signTransactionData(privHex, message string) (string, error) {
	b, err := hex.DecodeString(privHex)
	if err != nil {
		return "", err
	}
	defer zeroBytes(b)
	priv, _ := btcec.PrivKeyFromBytes(b)

	hMsg := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, priv.ToECDSA(), hMsg[:])
	if err != nil {
		return "", err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	var sigBytes [64]byte
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	return hex.EncodeToString(sigBytes[:]), nil
}

func verifyMessageSignature(pubKeyHex, address, message, sigHex string) (bool, error) {
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != 64 {
		return false, fmt.Errorf("Invalid signature format (64-byte hex expected)")
	}

	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != 64 {
		return false, fmt.Errorf("Invalid public key format (64-byte hex expected)")
	}

	cleanAddr := strings.TrimSpace(address)
	if cleanAddr != "" {
		h := sha256.Sum256(pubBytes)
		derivedAddr := "WNX" + strings.ToUpper(hex.EncodeToString(h[:16]))
		if derivedAddr != cleanAddr {
			return false, fmt.Errorf("Public key does not match specified wallet address (%s). Expected: %s", cleanAddr, derivedAddr)
		}
	}

	uncompressed := append([]byte{0x04}, pubBytes...)
	pubKey, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return false, fmt.Errorf("Failed to parse public key: %v", err)
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	h256 := sha256.Sum256([]byte(message))
	if ecdsa.Verify(pubKey.ToECDSA(), h256[:], r, s) {
		return true, nil
	}
	h1 := sha1.Sum([]byte(message))
	if ecdsa.Verify(pubKey.ToECDSA(), h1[:], r, s) {
		return true, nil
	}
	return false, fmt.Errorf("Cryptographic signature verification failed. Signature does not belong to specified key or message.")
}

func computePowHash(index int64, prevHash, merkle, minerAddr string, timestamp float64, nonce int64) string {
	raw := fmt.Sprintf("%d:%s:%s:%s:%.4f:%d", index, prevHash, merkle, minerAddr, timestamp, nonce)
	h1 := sha256.Sum256([]byte(raw))
	h1Hex := hex.EncodeToString(h1[:])
	h2 := sha256.Sum256([]byte(h1Hex))
	return hex.EncodeToString(h2[:])
}

func startInternalMiner(threads int) {
	minerLock.Lock()
	defer minerLock.Unlock()

	if minerState.Active {
		return
	}

	vaultLock.Lock()
	if activeVault == nil {
		vaultLock.Unlock()
		return
	}
	currWallet := *activeVault
	vaultLock.Unlock()

	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	minerState.Active = true
	minerState.Threads = threads
	stopMiner = make(chan struct{})

	numWorkers := threads
	var totalHashesAtomic int64

	for i := 0; i < numWorkers; i++ {
		wID := int64(i)
		go func(id int64) {
			client := &http.Client{Timeout: 3 * time.Second}
			for {
				select {
				case <-stopMiner:
					return
				default:
				}

				resp, err := client.Get(currWallet.NodeURL + "/api/mining/template")
				if err != nil {
					time.Sleep(2 * time.Second)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				var tmpl struct {
					BlockIndex   int64   `json:"block_index"`
					PrevHash     string  `json:"prev_hash"`
					MerkleRoot   string  `json:"merkle_root"`
					Target       string  `json:"target"`
					TargetPrefix string  `json:"target_prefix"`
					ServerTime   float64 `json:"server_time"`
				}
				if err := json.Unmarshal(body, &tmpl); err != nil {
					time.Sleep(2 * time.Second)
					continue
				}

				var clockDelta float64 = 0.0
				if tmpl.ServerTime > 0 {
					clockDelta = tmpl.ServerTime - (float64(time.Now().UnixNano()) / 1e9)
				}

				minerLock.Lock()
				minerState.ActiveTarget = tmpl.Target
				minerLock.Unlock()

				nonce := id * 10000000
				prefix := tmpl.TargetPrefix
				if prefix == "" && len(tmpl.Target) >= 6 {
					prefix = tmpl.Target[:6]
				}

				for k := 0; k < 50000; k++ {
					select {
					case <-stopMiner:
						return
					default:
					}

					nonce++
					atomic.AddInt64(&totalHashesAtomic, 1)
					ts := (float64(time.Now().UnixNano()) / 1e9) + clockDelta
					hash := computePowHash(tmpl.BlockIndex, tmpl.PrevHash, tmpl.MerkleRoot, currWallet.Address, ts, nonce)

					if strings.HasPrefix(hash, prefix) {
						payload := map[string]interface{}{
							"miner_address": currWallet.Address,
							"block_index":   tmpl.BlockIndex,
							"nonce":         nonce,
							"timestamp":     ts,
							"hash":          hash,
							"reported_hash": hash,
						}
						pBytes, _ := json.Marshal(payload)
						postResp, postErr := client.Post(currWallet.NodeURL+"/api/mining/submit", "application/json", bytes.NewBuffer(pBytes))
						if postErr == nil {
							var resMap map[string]interface{}
							_ = json.NewDecoder(postResp.Body).Decode(&resMap)
							postResp.Body.Close()
							s, _ := resMap["status"].(string)
							suc, _ := resMap["success"].(bool)
							if s == "success" || s == "ok" || s == "accepted" || suc {
								minerLock.Lock()
								minerState.BlocksMined++
								minerLock.Unlock()
								break
							}
						}
					}
				}
			}
		}(wID)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastH int64
		for {
			select {
			case <-stopMiner:
				return
			case <-ticker.C:
				curH := atomic.LoadInt64(&totalHashesAtomic)
				diff := curH - lastH
				lastH = curH

				minerLock.Lock()
				minerState.TotalHashes = curH
				if diff >= 1000000 {
					minerState.HashRate = fmt.Sprintf("%.2f MH/s", float64(diff)/1000000.0)
				} else if diff >= 1000 {
					minerState.HashRate = fmt.Sprintf("%.2f KH/s", float64(diff)/1000.0)
				} else {
					minerState.HashRate = fmt.Sprintf("%d H/s", diff)
				}
				minerLock.Unlock()
			}
		}
	}()
}

func stopInternalMiner() {
	minerLock.Lock()
	defer minerLock.Unlock()
	if !minerState.Active {
		return
	}
	minerState.Active = false
	minerState.HashRate = "0 H/s"
	if stopMiner != nil {
		close(stopMiner)
		stopMiner = nil
	}
}

func extractNativeRuntimeAssets() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	rtDir := filepath.Join(getWalletDir(), "runtime")
	_ = os.MkdirAll(rtDir, 0700)
	_ = os.WriteFile(filepath.Join(rtDir, "winex_wallet_gui.py"), embeddedPyQtGUI, 0700)
	_ = os.WriteFile(filepath.Join(rtDir, "winex_core.py"), embeddedWinexCore, 0600)
	_ = os.WriteFile(filepath.Join(rtDir, "winex_logo.png"), embeddedLogoPng, 0644)
	return rtDir
}

func cleanEnvForSystemPython() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PYTHONHOME=") ||
			strings.HasPrefix(e, "PYTHONPATH=") ||
			strings.HasPrefix(e, "LD_LIBRARY_PATH=") ||
			strings.HasPrefix(e, "LD_PRELOAD=") ||
			strings.HasPrefix(e, "QT_LOGGING_RULES=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "QT_LOGGING_RULES=qt.qpa.services=false;qt.qpa.*=false;qt.qpa.wayland=false")
	return env
}

func tryLaunchNativeQtWallet(rtDir string) bool {
	if runtime.GOOS != "linux" || rtDir == "" {
		return false
	}
	guiScript := filepath.Join(rtDir, "winex_wallet_gui.py")
	pyCandidates := []string{"/usr/bin/python3", "python3", "python"}
	cleanEnv := cleanEnvForSystemPython()
	for _, py := range pyCandidates {
		pyPath, err := exec.LookPath(py)
		if err != nil {
			continue
		}
		chk := exec.Command(pyPath, "-c", "import PySide6, requests, qrcode, ecdsa, mnemonic, cryptography")
		chk.Env = cleanEnv
		if chk.Run() == nil {
			cmd := exec.Command(pyPath, guiScript)
			cmd.Dir = rtDir
			cmd.Env = cleanEnv
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			return true
		}
	}
	return false
}

func openDesktopWindow(url string) {
	if runtime.GOOS == "windows" {
		edgePaths := []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
		for _, p := range edgePaths {
			if _, err := os.Stat(p); err == nil {
				cmd := exec.Command(p, fmt.Sprintf("--app=%s", url), "--window-size=1140,780")
				if err := cmd.Start(); err == nil {
					return
				}
			}
		}

		chromePath := `C:\Program Files\Google\Chrome\Application\chrome.exe`
		if _, err := os.Stat(chromePath); err == nil {
			cmd := exec.Command(chromePath, fmt.Sprintf("--app=%s", url), "--window-size=1140,780")
			if err := cmd.Start(); err == nil {
				return
			}
		}

		_ = openURLNative(url)
		return
	}

	_ = openURLNative(url)
}

func validateCSRF(r *http.Request) bool {
	hdr := strings.TrimSpace(r.Header.Get("X-WINEX-Token"))
	if hdr != "" && subtle.ConstantTimeCompare([]byte(hdr), []byte(csrfToken)) == 1 {
		return true
	}
	q := strings.TrimSpace(r.URL.Query().Get("token"))
	if q != "" && subtle.ConstantTimeCompare([]byte(q), []byte(csrfToken)) == 1 {
		return true
	}
	return false
}

func main() {
	enableMemoryProtection()
	initCSRFToken()
	purgeLegacyVaults()

	// Ensure background WINEX_Node is running on 127.0.0.1:8081 to support the network
	_ = ensureBackgroundNodeRunning()

	minerState.Threads = runtime.NumCPU()

	mux := http.NewServeMux()

	mux.HandleFunc("/winex_logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(embeddedLogoPng)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(embeddedFaviconIco)
	})

	// 1. Vault Lifecycle & Authentication API
	mux.HandleFunc("/api/app_state", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		defer vaultLock.Unlock()

		hasVault := hasExistingVault()
		state := "uninitialized"
		if hasVault {
			if activeVault != nil {
				state = "unlocked"
			} else {
				state = "locked"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"state":     state,
			"has_vault": hasVault,
		})
	})

	mux.HandleFunc("/api/onboarding/generate_seed", func(w http.ResponseWriter, r *http.Request) {
		mnemonic, err := generateNewMnemonic()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"seed": mnemonic})
	})

	mux.HandleFunc("/api/onboarding/finalize_setup", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Seed     string `json:"seed"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if !bip39.IsMnemonicValid(strings.TrimSpace(req.Seed)) {
			http.Error(w, "Invalid 12-word recovery seed phrase", 400)
			return
		}
		if len(req.Password) < 4 {
			http.Error(w, "Password must be at least 4 characters", 400)
			return
		}

		wData := deriveWalletFromMnemonic(req.Seed, defaultRemoteNode)
		ev, err := encryptVault(wData, req.Password)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		if err := saveVaultToDisk(ev); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		syncMinerAddressFile(wData.Address)

		vaultLock.Lock()
		activeVault = &wData
		activePw = req.Password
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"address": wData.Address,
		})
	})

	mux.HandleFunc("/api/vault/unlock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		ev, err := loadVaultFromDisk()
		if err != nil {
			http.Error(w, "Vault file not found", 404)
			return
		}

		wData, err := decryptVault(ev, req.Password)
		if err != nil {
			http.Error(w, err.Error(), 401)
			return
		}

		syncMinerAddressFile(wData.Address)

		vaultLock.Lock()
		activeVault = wData
		activePw = req.Password
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"address": wData.Address,
		})
	})

	mux.HandleFunc("/api/vault/lock", func(w http.ResponseWriter, r *http.Request) {
		stopInternalMiner()
		vaultLock.Lock()
		purgeSensitiveMemoryLocked()
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "locked"})
	})

	// 2. Wallet Core Services
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		if curW == nil {
			http.Error(w, "Wallet is locked", 401)
			return
		}

		client := &http.Client{Timeout: 3 * time.Second}
		var totalBal float64 = 0.0
		var height int64 = 0
		var poolRem float64 = 10000000.0
		var blkReward float64 = 40.0
		nodeOnline := false

		vaultLock.Lock()
		if len(activeVault.Accounts) == 0 {
			activeVault.Accounts = []HDAccount{deriveHDAccount(activeVault.SeedPhrase, 0, "Primary Account")}
		}
		accountsCopy := make([]HDAccount, len(activeVault.Accounts))
		copy(accountsCopy, activeVault.Accounts)
		currActiveAddr := activeVault.Address
		vaultLock.Unlock()

		for i := range accountsCopy {
			addr := accountsCopy[i].Address
			accountsCopy[i].PrivateKey = "" // Redact private key from JSON API responses
			var aBal float64 = 0.0
			resp, err := client.Get(curW.NodeURL + "/api/balance/" + addr)
			if err == nil {
				nodeOnline = true
				var bMap map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&bMap); err == nil {
					if v, ok := bMap["balance"].(float64); ok {
						aBal = v
					}
				}
				resp.Body.Close()
			}
			accountsCopy[i].Balance = aBal
			accountsCopy[i].IsActive = (addr == currActiveAddr)
			totalBal += aBal
		}

		respState, err2 := client.Get(curW.NodeURL + "/api/state")
		if err2 == nil {
			var sMap map[string]interface{}
			_ = json.NewDecoder(respState.Body).Decode(&sMap)
			respState.Body.Close()
			if h, ok := sMap["block_height"].(float64); ok {
				height = int64(h)
			}
			if p, ok := sMap["pool_remaining"].(float64); ok {
				poolRem = p
			}
			if r, ok := sMap["block_reward"].(float64); ok {
				blkReward = r
			}
		}

		minerLock.Lock()
		mActive := minerState.Active
		mHR := minerState.HashRate
		mTH := minerState.TotalHashes
		mBM := minerState.BlocksMined
		mTh := minerState.Threads
		minerLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"address":        currActiveAddr,
			"public_key":     curW.PublicKey,
			"balance":        totalBal,
			"block_height":   height,
			"pool_remaining": poolRem,
			"block_reward":   blkReward,
			"node_url":       curW.NodeURL,
			"node_connected": nodeOnline,
			"mining_active":  mActive,
			"hash_rate":      mHR,
			"total_hashes":   mTH,
			"blocks_mined":   mBM,
			"threads":        mTh,
			"total_cpus":     runtime.NumCPU(),
			"network_fee":    0.0,
			"accounts":       accountsCopy,
		})
	})

	mux.HandleFunc("/api/wallet/new_address", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		defer vaultLock.Unlock()
		if activeVault == nil {
			http.Error(w, "Wallet is locked", 401)
			return
		}
		if len(activeVault.Accounts) == 0 {
			activeVault.Accounts = []HDAccount{deriveHDAccount(activeVault.SeedPhrase, 0, "Primary Account")}
		}
		maxIdx := -1
		for _, a := range activeVault.Accounts {
			if a.Index > maxIdx {
				maxIdx = a.Index
			}
		}
		nextIdx := maxIdx + 1
		newAcc := deriveHDAccount(activeVault.SeedPhrase, nextIdx, fmt.Sprintf("Account #%d", nextIdx))
		activeVault.Accounts = append(activeVault.Accounts, newAcc)
		if activePw != "" {
			if ev, err := encryptVault(*activeVault, activePw); err == nil {
				_ = saveVaultToDisk(ev)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(newAcc)
	})

	mux.HandleFunc("/api/wallet/set_active", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Index int `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		vaultLock.Lock()
		defer vaultLock.Unlock()
		if activeVault == nil {
			http.Error(w, "Wallet is locked", 401)
			return
		}

		var targetAcc *HDAccount
		for i := range activeVault.Accounts {
			if activeVault.Accounts[i].Index == req.Index {
				targetAcc = &activeVault.Accounts[i]
				break
			}
		}
		if targetAcc == nil {
			http.Error(w, "Account index not found", 404)
			return
		}

		activeVault.Address = targetAcc.Address
		activeVault.PublicKey = targetAcc.PublicKey
		activeVault.PrivateKey = targetAcc.PrivateKey
		syncMinerAddressFile(targetAcc.Address)

		if activePw != "" {
			if ev, err := encryptVault(*activeVault, activePw); err == nil {
				_ = saveVaultToDisk(ev)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"address": targetAcc.Address,
		})
	})

	mux.HandleFunc("/api/wallet/scan_accounts", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		if activeVault == nil {
			vaultLock.Unlock()
			http.Error(w, "Wallet is locked", 401)
			return
		}
		seed := activeVault.SeedPhrase
		nodeURL := activeVault.NodeURL
		existingIndices := make(map[int]bool)
		for _, a := range activeVault.Accounts {
			existingIndices[a.Index] = true
		}
		vaultLock.Unlock()

		discovered := discoverHDAccounts(seed, nodeURL)

		vaultLock.Lock()
		addedCount := 0
		for _, d := range discovered {
			if !existingIndices[d.Index] {
				activeVault.Accounts = append(activeVault.Accounts, d)
				addedCount++
			}
		}
		if addedCount > 0 && activePw != "" {
			if ev, err := encryptVault(*activeVault, activePw); err == nil {
				_ = saveVaultToDisk(ev)
			}
		}
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"discovered": addedCount,
		})
	})

	mux.HandleFunc("/api/wallet/qrcode.png", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		if curW == nil {
			http.Error(w, "Unauthorized", 401)
			return
		}

		uri := fmt.Sprintf("winex:%s", curW.Address)
		png, err := qrcode.Encode(uri, qrcode.Medium, 280)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	})

	mux.HandleFunc("/api/miner/toggle", func(w http.ResponseWriter, r *http.Request) {
		minerLock.Lock()
		active := minerState.Active
		minerLock.Unlock()

		if active {
			stopInternalMiner()
		} else {
			thStr := r.URL.Query().Get("threads")
			threads, _ := strconv.Atoi(thStr)
			if threads <= 0 {
				threads = runtime.NumCPU()
			}
			startInternalMiner(threads)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	})

	
	mux.HandleFunc("/api/blocks", func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{Timeout: 3 * time.Second}
		endpoints := []string{"http://127.0.0.1:8081/api/blocks?limit=30", defaultRemoteNode + "/api/blocks?limit=30"}
		for _, ep := range endpoints {
			resp, err := client.Get(ep)
			if err == nil && resp.StatusCode == 200 {
				defer resp.Body.Close()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.Copy(w, resp.Body)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})

	mux.HandleFunc("/api/transactions", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		if curW == nil {
			http.Error(w, "Unauthorized", 401)
			return
		}

		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Get(curW.NodeURL + "/api/transactions/recent?limit=25")
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, resp.Body)
	})

	// Zero-Fee Send Transaction
	mux.HandleFunc("/api/wallet/send", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		if curW == nil {
			http.Error(w, "Wallet is locked", 401)
			return
		}

		var req struct {
			FromAddress string  `json:"from_address"`
			Recipient   string  `json:"recipient"`
			Amount      float64 `json:"amount"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		req.Recipient = strings.TrimSpace(req.Recipient)
		req.FromAddress = strings.TrimSpace(req.FromAddress)
		if math.IsNaN(req.Amount) || math.IsInf(req.Amount, 0) || req.Amount < 0.00000001 || req.Amount > 10000000.0 {
			http.Error(w, "Invalid amount parameter (min 0.00000001 WNX)", 400)
			return
		}
		if !strings.HasPrefix(req.Recipient, "WNX") || len(req.Recipient) < 20 || len(req.Recipient) > 42 {
			http.Error(w, "Invalid recipient address format", 400)
			return
		}

		vaultLock.Lock()
		var sourceAcc *HDAccount
		if req.FromAddress != "" {
			for i := range curW.Accounts {
				if curW.Accounts[i].Address == req.FromAddress {
					sourceAcc = &curW.Accounts[i]
					break
				}
			}
		}
		if sourceAcc == nil {
			for i := range curW.Accounts {
				if curW.Accounts[i].Address == curW.Address {
					sourceAcc = &curW.Accounts[i]
					break
				}
			}
		}
		if sourceAcc == nil && len(curW.Accounts) > 0 {
			sourceAcc = &curW.Accounts[0]
		}
		if sourceAcc == nil {
			vaultLock.Unlock()
			http.Error(w, "No active spending account found", 400)
			return
		}

		senderAddr := sourceAcc.Address
		senderPrivKey := sourceAcc.PrivateKey
		senderPubKey := sourceAcc.PublicKey
		vaultLock.Unlock()

		if req.Recipient == senderAddr {
			http.Error(w, "Cannot transfer funds to the same address", 400)
			return
		}

		// Retrieve server network time to protect against client/VM clock skew
		client := &http.Client{Timeout: 5 * time.Second}
		var ts float64 = float64(time.Now().UnixNano()) / 1e9
		tmplResp, errTmpl := client.Get(curW.NodeURL + "/api/mining/template")
		if errTmpl == nil {
			var tMap map[string]interface{}
			if err := json.NewDecoder(tmplResp.Body).Decode(&tMap); err == nil {
				if st, ok := tMap["server_time"].(float64); ok && st > 0 {
					ts = st
				}
			}
			tmplResp.Body.Close()
		}

		rawMsg := fmt.Sprintf("%s:%s:%.8f:%.8f:%.4f", senderAddr, req.Recipient, req.Amount, 0.0, ts)
		sig, err := signTransactionData(senderPrivKey, rawMsg)
		if err != nil {
			http.Error(w, "Signing error: "+err.Error(), 500)
			return
		}

		payload := map[string]interface{}{
			"sender":     senderAddr,
			"recipient":  req.Recipient,
			"amount":     req.Amount,
			"fee":        0.0,
			"public_key": senderPubKey,
			"signature":  sig,
			"timestamp":  ts,
		}

		pBytes, _ := json.Marshal(payload)
		resp, err := client.Post(curW.NodeURL+"/api/transaction/send", "application/json", bytes.NewBuffer(pBytes))
		if err != nil {
			http.Error(w, "Unable to reach network nodes: "+err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// Sign Arbitrary Message
	mux.HandleFunc("/api/wallet/sign_message", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		if curW == nil {
			http.Error(w, "Wallet is locked or uninitialized", 401)
			return
		}

		sig, err := signTransactionData(curW.PrivateKey, req.Message)
		if err != nil {
			http.Error(w, "Signing error: "+err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"address":    curW.Address,
			"public_key": curW.PublicKey,
			"message":    req.Message,
			"signature":  sig,
			"status":     "ok",
		})
	})

	// Verify Arbitrary Message
	mux.HandleFunc("/api/wallet/verify_message", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address   string `json:"address"`
			PublicKey string `json:"public_key"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		valid, err := verifyMessageSignature(req.PublicKey, req.Address, req.Message, req.Signature)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   valid,
			"address": req.Address,
			"status":  "ok",
		})
	})

	// Interactive CLI Console Execution
	mux.HandleFunc("/api/cli/execute", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		rawCmd := strings.TrimSpace(req.Command)
		if rawCmd == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"output": ""})
			return
		}

		vaultLock.Lock()
		curW := activeVault
		vaultLock.Unlock()

		parts := strings.Fields(rawCmd)
		cmd := strings.ToLower(parts[0])

		var output string

		switch cmd {
		case "help":
			output = `WINEX Interactive CLI Console v2.5
Available Commands:
  help                                  Show this command reference
  getinfo                               Query live node state, height, and 10,000,000 WNX pool
  balance                               Inspect confirmed wallet balance
  address                               Display active receiving WNX address
  pubkey                                Display SECP256k1 uncompressed public key
  send <recipient> <amount>             Broadcast 0.0000 WNX fee transfer
  signmessage <message>                 Sign message with ECDSA SECP256k1
  verifymessage <addr> <pub> <sig> <m>  Verify ECDSA message signature
  transactions                          List recent ledger transactions
  peers                                 List active P2P mesh peers
  clear                                 Clear console buffer`

		case "getinfo":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(curW.NodeURL + "/api/state")
				if err != nil {
					output = fmt.Sprintf("Node unreachable: %v", err)
				} else {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var pretty bytes.Buffer
					_ = json.Indent(&pretty, body, "", "  ")
					output = pretty.String()
				}
			}

		case "balance":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(curW.NodeURL + "/api/balance/" + curW.Address)
				if err != nil {
					output = fmt.Sprintf("Failed to query balance: %v", err)
				} else {
					var bMap map[string]interface{}
					_ = json.NewDecoder(resp.Body).Decode(&bMap)
					resp.Body.Close()
					bal := bMap["balance"]
					output = fmt.Sprintf("Address : %s\nBalance : %v WNX\nFee     : 0.0000 WNX (Zero-Fee Protocol)", curW.Address, bal)
				}
			}

		case "address":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				output = curW.Address
			}

		case "pubkey":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				output = curW.PublicKey
			}

		case "signmessage":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else if len(parts) < 2 {
				output = "Usage: signmessage <message_text>"
			} else {
				msg := strings.Join(parts[1:], " ")
				sig, err := signTransactionData(curW.PrivateKey, msg)
				if err != nil {
					output = fmt.Sprintf("Signing error: %v", err)
				} else {
					output = fmt.Sprintf("Address    : %s\nPublic Key : %s\nMessage    : %s\nSignature  : %s", curW.Address, curW.PublicKey, msg, sig)
				}
			}

		case "verifymessage":
			if len(parts) < 5 {
				output = "Usage: verifymessage <address> <pubkey> <signature> <message...>"
			} else {
				addr := parts[1]
				pk := parts[2]
				sig := parts[3]
				msg := strings.Join(parts[4:], " ")
				valid, err := verifyMessageSignature(pk, addr, msg, sig)
				if err != nil {
					output = fmt.Sprintf("Verification failed: %v", err)
				} else if valid {
					output = fmt.Sprintf("[VALID SIGNATURE] Message verified for address %s (%s)", addr, pk[:16]+"...")
				} else {
					output = "[INVALID SIGNATURE]"
				}
			}

		case "send":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else if len(parts) < 3 {
				output = "Usage: send <recipient_address> <amount>"
			} else {
				recip := parts[1]
				amt, err := strconv.ParseFloat(parts[2], 64)
				if err != nil || amt <= 0 {
					output = "Error: Invalid transfer amount."
				} else {
					ts := float64(time.Now().UnixNano()) / 1e9
					rawMsg := fmt.Sprintf("%s:%s:%.4f:%.4f:%.4f", curW.Address, recip, amt, 0.0, ts)
					sig, err := signTransactionData(curW.PrivateKey, rawMsg)
					if err != nil {
						output = fmt.Sprintf("Signing error: %v", err)
					} else {
						payload := map[string]interface{}{
							"sender":     curW.Address,
							"recipient":  recip,
							"amount":     amt,
							"fee":        0.0,
							"public_key": curW.PublicKey,
							"signature":  sig,
							"timestamp":  ts,
						}
						pBytes, _ := json.Marshal(payload)
						client := &http.Client{Timeout: 5 * time.Second}
						resp, err := client.Post(curW.NodeURL+"/api/transaction/send", "application/json", bytes.NewBuffer(pBytes))
						if err != nil {
							output = fmt.Sprintf("Failed to broadcast to node: %v", err)
						} else {
							body, _ := io.ReadAll(resp.Body)
							resp.Body.Close()
							output = string(body)
						}
					}
				}
			}

		case "transactions":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				client := &http.Client{Timeout: 4 * time.Second}
				resp, err := client.Get(curW.NodeURL + "/api/transactions/recent?limit=10")
				if err != nil {
					output = fmt.Sprintf("Error: %v", err)
				} else {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var pretty bytes.Buffer
					_ = json.Indent(&pretty, body, "", "  ")
					output = pretty.String()
				}
			}

		case "peers":
			if curW == nil {
				output = "Error: Wallet is locked."
			} else {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(curW.NodeURL + "/api/p2p/peers")
				if err != nil {
					output = fmt.Sprintf("Error: %v", err)
				} else {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var pretty bytes.Buffer
					_ = json.Indent(&pretty, body, "", "  ")
					output = pretty.String()
				}
			}

		default:
			output = fmt.Sprintf("Unknown command: '%s'. Type 'help' for command list.", cmd)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"output": output})
	})

	mux.HandleFunc("/api/settings/export_seed", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		vaultLock.Lock()
		defer vaultLock.Unlock()
		if activeVault == nil || subtle.ConstantTimeCompare([]byte(req.Password), []byte(activePw)) != 1 {
			http.Error(w, "Incorrect password", 401)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"seed_phrase": activeVault.SeedPhrase,
		})
	})

	mux.HandleFunc("/api/settings/update_node", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NodeURL string `json:"node_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		node := strings.TrimSpace(req.NodeURL)
		if node == "" {
			node = defaultRemoteNode
		}

		vaultLock.Lock()
		if activeVault != nil {
			activeVault.NodeURL = node
			if activePw != "" {
				ev, _ := encryptVault(*activeVault, activePw)
				_ = saveVaultToDisk(ev)
			}
		}
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	})

	mux.HandleFunc("/api/settings/reset_wallet", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		vaultLock.Lock()
		if activeVault == nil || subtle.ConstantTimeCompare([]byte(req.Password), []byte(activePw)) != 1 {
			vaultLock.Unlock()
			http.Error(w, "Incorrect password", 401)
			return
		}
		stopInternalMiner()
		purgeSensitiveMemoryLocked()
		_ = os.Remove(getVaultPath())
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	})

	mux.HandleFunc("/api/vault/wipe_and_reset", func(w http.ResponseWriter, r *http.Request) {
		vaultLock.Lock()
		stopInternalMiner()
		purgeSensitiveMemoryLocked()
		_ = os.Remove(getVaultPath())
		_ = os.Remove(filepath.Join(getWalletDir(), "vault.json"))
		_ = os.Remove(filepath.Join(getWalletDir(), "vault.v2.json"))
		_ = os.Remove(filepath.Join(getWalletDir(), "wallet.dat"))
		_ = os.Remove(filepath.Join(getWalletDir(), "miner_address.txt"))
		vaultLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	})

	// 3. UI Desktop Window Endpoint
	renderedUI := strings.ReplaceAll(htmlUI, "__CSRF_TOKEN__", csrfToken)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		_, _ = w.Write([]byte(renderedUI))
	})

	securedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self' data: 'unsafe-inline';")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !validateCSRF(r) {
				http.Error(w, "Forbidden: invalid session token", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})

	rtDir := extractNativeRuntimeAssets()

	// Launch Native Qt6 Electrum Desktop GUI directly if available
	if tryLaunchNativeQtWallet(rtDir) {
		return
	}


	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("Error starting local engine: %v\n", err)
		return
	}
	port := listener.Addr().(*net.TCPAddr).Port
	appURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	go func() {
		time.Sleep(150 * time.Millisecond)
		openDesktopWindow(appURL)
	}()

	_ = http.Serve(listener, securedHandler)
}

const htmlUI = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WINEX Core Wallet</title>
<link rel="icon" type="image/png" href="/winex_logo.png">
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-canvas: #08090c;
    --bg-surface: #0c0f16;
    --bg-card: #111621;
    --bg-elevated: #161c2b;
    --border-hairline: #1e2536;
    --border-strong: #2e3852;
    --text-main: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --accent-emerald: #10b981;
    --accent-green: #22c55e;
    --accent-cyan: #38bdf8;
    --accent-danger: #f43f5e;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background-color: var(--bg-canvas);
    color: var(--text-main);
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 13.5px;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    user-select: none;
    -webkit-font-smoothing: antialiased;
  }

  .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
  }

  /* Titlebar */
  .titlebar {
    height: 34px;
    background-color: var(--bg-surface);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 14px;
    border-bottom: 1px solid var(--border-hairline);
    font-size: 12.5px;
    font-weight: 600;
  }
  .title-brand {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .title-logo {
    width: 18px;
    height: 18px;
    border-radius: 50%;
  }

  /* Menu Bar */
  .menubar {
    height: 28px;
    background-color: var(--bg-surface);
    display: flex;
    align-items: center;
    padding: 0 8px;
    border-bottom: 1px solid var(--border-hairline);
    font-size: 12px;
  }
  .menu-item {
    position: relative;
    padding: 4px 10px;
    color: var(--text-secondary);
    cursor: pointer;
    border-radius: 3px;
  }
  .menu-item:hover {
    background-color: var(--bg-card);
    color: var(--text-main);
  }
  .dropdown {
    display: none;
    position: absolute;
    top: 26px;
    left: 0;
    background-color: var(--bg-card);
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    min-width: 180px;
    z-index: 1000;
    box-shadow: 0 8px 24px rgba(0,0,0,0.6);
  }
  .dropdown.show { display: block; }
  .drop-link {
    padding: 8px 14px;
    display: block;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 12px;
  }
  .drop-link:hover {
    background-color: var(--bg-elevated);
    color: var(--accent-emerald);
  }

  /* Tabs Bar (Horizontal like Linux) */
  .tab-bar {
    height: 36px;
    background-color: var(--bg-surface);
    display: flex;
    border-bottom: 1px solid var(--border-hairline);
    padding: 0 8px;
  }
  .tab-btn {
    padding: 0 16px;
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s ease;
  }
  .tab-btn:hover {
    color: var(--text-main);
  }
  .tab-btn.active {
    color: #ffffff;
    font-weight: 600;
    border-bottom: 2.5px solid var(--accent-emerald);
  }

  /* Main Workspace */
  .workspace {
    flex: 1;
    overflow: hidden;
    position: relative;
    display: flex;
    flex-direction: column;
  }
  .tab-pane {
    display: none;
    flex: 1;
    overflow-y: auto;
    flex-direction: column;
  }
  .tab-pane.active {
    display: flex;
  }

  /* History Tab */
  .history-toolbar {
    height: 44px;
    background-color: var(--bg-surface);
    border-bottom: 1px solid var(--border-hairline);
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 10px;
  }
  .filter-input {
    flex: 1;
    height: 28px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-hairline);
    border-radius: 3px;
    color: var(--text-secondary);
    padding: 0 10px;
    font-size: 12px;
    outline: none;
  }
  .filter-input:focus {
    border-color: var(--border-strong);
    color: var(--text-main);
  }
  .btn-sync {
    height: 28px;
    padding: 0 14px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-strong);
    color: var(--text-main);
    border-radius: 3px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }
  .btn-sync:hover {
    background-color: var(--bg-elevated);
  }

  .grid-wrap {
    flex: 1;
    overflow-y: auto;
    background-color: var(--bg-canvas);
  }
  .ledger-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }
  .ledger-table th {
    background-color: var(--bg-surface);
    color: var(--text-muted);
    font-size: 11.5px;
    font-weight: 600;
    text-align: left;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-hairline);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .ledger-table td {
    padding: 7px 12px;
    border-bottom: 1px solid #131722;
  }
  .ledger-table tr:nth-child(even) {
    background-color: rgba(255,255,255,0.015);
  }
  .ledger-table tr:hover {
    background-color: var(--bg-card);
  }
  .cell-state {
    color: var(--accent-green);
    font-weight: 600;
    width: 70px;
  }
  .cell-ref {
    color: var(--text-main);
  }
  .cell-value {
    color: var(--accent-green);
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    text-align: right;
    width: 140px;
  }
  .cell-time {
    color: var(--text-muted);
    text-align: right;
    width: 160px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
  }

  /* Simple Card Panes */
  .pane-content {
    padding: 24px 32px;
    max-width: 880px;
  }
  .pane-h1 {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 4px;
  }
  .pane-sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 20px;
  }
  .form-group {
    margin-bottom: 16px;
  }
  .form-label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 6px;
  }
  .form-input {
    width: 100%;
    max-width: 580px;
    height: 36px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-hairline);
    border-radius: 4px;
    color: var(--text-main);
    padding: 0 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    outline: none;
  }
  .form-input:focus { border-color: var(--accent-emerald); }
  .btn-pri {
    height: 38px;
    padding: 0 20px;
    background-color: var(--accent-emerald);
    color: #000;
    border: none;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
  }
  .btn-pri:hover { opacity: 0.92; }

  /* Console */
  .cli-output {
    flex: 1;
    background-color: var(--bg-canvas);
    color: var(--text-main);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    padding: 14px;
    overflow-y: auto;
    white-space: pre-wrap;
    line-height: 1.5;
  }
  .cli-input-bar {
    height: 36px;
    background-color: var(--bg-surface);
    border-top: 1px solid var(--border-hairline);
    display: flex;
    align-items: center;
    padding: 0 10px;
  }
  .cli-input {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--accent-emerald);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    outline: none;
  }

  /* Status Bar */
  .statusbar {
    height: 26px;
    background-color: var(--bg-surface);
    border-top: 1px solid var(--border-hairline);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 12px;
    font-size: 11.5px;
  }
  .sb-left {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .sb-bal {
    font-weight: 700;
    color: var(--text-main);
  }
  .sb-hide {
    color: var(--text-muted);
    cursor: pointer;
    text-decoration: underline;
    font-size: 11px;
  }
  .sb-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .sb-node {
    color: var(--accent-green);
    font-weight: 700;
  }
  .sb-meta {
    color: var(--text-muted);
  }

  /* Modal */
  .modal-overlay {
    position: fixed;
    inset: 0;
    background-color: rgba(0,0,0,0.85);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
  }
  .modal-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    width: 480px;
    padding: 28px;
    box-shadow: 0 12px 36px rgba(0,0,0,0.8);
  }
</style>
</head>
<body>

<!-- Titlebar -->
<div class="titlebar">
  <div class="title-brand">
    <img src="/winex_logo.png" class="title-logo" alt="WNX" onerror="this.style.display='none'">
    <span>WINEX Core Wallet</span>
  </div>
  <div style="font-size:11px; color:var(--text-muted);">Electrum Sovereign Architecture v3.6.0</div>
</div>

<!-- Menubar -->
<div class="menubar">
  <div class="menu-item" onclick="toggleMenu('mFile', event)">File
    <div id="mFile" class="dropdown">
      <a href="#" class="drop-link" onclick="promptBackupSeed()">Back Up Recovery Seed</a>
      <a href="#" class="drop-link" onclick="promptResetKeystore()">New / Reset Keystore...</a>
      <a href="#" class="drop-link" onclick="lockVault()">Lock Wallet</a>
      <a href="#" class="drop-link" onclick="window.close()">Exit</a>
    </div>
  </div>
  <div class="menu-item" onclick="toggleMenu('mWallet', event)">Wallet
    <div id="mWallet" class="dropdown">
      <a href="#" class="drop-link" onclick="switchTab('history')">History</a>
      <a href="#" class="drop-link" onclick="switchTab('addresses')">Addresses</a>
      <a href="#" class="drop-link" onclick="copyCurrentAddress()">Copy Receiving Address</a>
    </div>
  </div>
  <div class="menu-item" onclick="toggleMenu('mTools', event)">Tools
    <div id="mTools" class="dropdown">
      <a href="#" class="drop-link" onclick="switchTab('console')">Interactive Console</a>
      <a href="#" class="drop-link" onclick="switchTab('network')">Network Telemetry</a>
    </div>
  </div>
  <div class="menu-item" onclick="toggleMenu('mHelp', event)">Help
    <div id="mHelp" class="dropdown">
      <a href="#" class="drop-link" onclick="switchTab('spec')">Protocol Specification</a>
      <a href="#" class="drop-link" onclick="alert('WINEX Core Sovereign Wallet v3.6.0\nConsensus: Dual-Pass SHA-256 Proof-of-Work')">About WINEX</a>
    </div>
  </div>
</div>

<!-- Tab Bar -->
<div class="tab-bar">
  <button class="tab-btn active" onclick="switchTab('history')">History</button>
  <button class="tab-btn" onclick="switchTab('send')">Send</button>
  <button class="tab-btn" onclick="switchTab('receive')">Receive</button>
  <button class="tab-btn" onclick="switchTab('addresses')">Addresses</button>
  <button class="tab-btn" onclick="switchTab('console')">Console</button>
  <button class="tab-btn" onclick="switchTab('network')">Network</button>
  <button class="tab-btn" onclick="switchTab('prefs')">Preferences</button>
  <button class="tab-btn" onclick="switchTab('spec')">Specification</button>
</div>

<!-- Workspace -->
<div class="workspace">

  <!-- 1. History Pane -->
  <div id="pane-history" class="tab-pane active">
    <div class="history-toolbar">
      <input type="text" id="filterInput" class="filter-input" placeholder="Filter ledger by block height, hash, or address..." oninput="filterHistoryTable()">
      <button class="btn-sync" onclick="refreshDashboard()">Sync Ledger</button>
    </div>
    <div class="grid-wrap">
      <table class="ledger-table">
        <thead>
          <tr>
            <th style="width:70px;">State</th>
            <th>Block / Digest Reference</th>
            <th style="width:140px; text-align:right;">Subsidy / Value</th>
            <th style="width:160px; text-align:right;">Timestamp</th>
          </tr>
        </thead>
        <tbody id="historyBody">
          <tr><td colspan="4" style="text-align:center; padding:32px; color:var(--text-muted);">Synchronizing sovereign ledger...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- 2. Send Pane -->
  <div id="pane-send" class="tab-pane">
    <div class="pane-content" style="max-width:560px;">
      <h1 class="pane-h1">Send WINEX (WNX)</h1>
      <div class="pane-sub">0.0000 WNX ZERO PROTOCOL NETWORK FEE</div>
      <div class="form-group" style="margin-bottom:14px;">
        <label class="form-label">From Account (Source):</label>
        <select id="sendSourceAccount" class="form-input" style="width:100%; height:36px;" onchange="updateSendAccountBal()"></select>
      </div>
      <div class="form-group" style="margin-bottom:14px;">
        <label class="form-label">Recipient Address (WNX...):</label>
        <input type="text" id="inpRecipient" class="form-input" placeholder="WNX...">
      </div>
      <div class="form-group" style="margin-bottom:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <label class="form-label" style="margin-bottom:0;">Amount (WNX):</label>
          <span id="sendAvailableBal" style="font-size:11.5px; color:var(--accent-cyan); cursor:pointer;" onclick="setSendMaxAmount()">Available: 0.0000 WNX (Use Max)</span>
        </div>
        <div style="display:flex; gap:8px;">
          <input type="number" id="inpAmount" class="form-input" value="1.00000000" step="0.00000001" min="0.00000001" style="flex:1;">
          <button type="button" class="btn-pri" style="background:#1e2536; border:1px solid var(--border-strong); color:var(--text-secondary); width:64px;" onclick="setSendMaxAmount()">MAX</button>
        </div>
      </div>
      <button class="btn-pri" style="width:100%; height:38px; font-size:13.5px;" onclick="doSendTransaction()">Sign &amp; Broadcast Transaction</button>
      <div id="sendResult" style="margin-top:14px; font-size:12.5px;"></div>
    </div>
  </div>

  <!-- 3. Receive Pane -->
  <div id="pane-receive" class="tab-pane">
    <div class="pane-content">
      <h1 class="pane-h1">Receive WINEX (WNX)</h1>
      <div class="pane-sub">SHARE YOUR DETERMINISTIC SEED-DERIVED ADDRESS</div>
      <div style="background:#fff; width:200px; height:200px; padding:10px; border-radius:4px; margin-bottom:14px;">
        <img id="recvQr" src="" style="width:180px; height:180px;" alt="QR Code">
      </div>
      <div id="recvAddressText" class="mono" style="font-size:13px; color:var(--accent-cyan); margin-bottom:14px;">WNX...</div>
      <button class="btn-pri" onclick="copyCurrentAddress()">Copy Receiving Address</button>
    </div>
  </div>

  <!-- 4. Addresses Pane -->
  <div id="pane-addresses" class="tab-pane">
    <div class="pane-content" style="display:flex; flex-direction:column; height:calc(100vh - 130px);">
      <div style="display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:12px;">
        <div>
          <h1 class="pane-h1">HD Address Book (BIP-39 / SECP256k1)</h1>
          <div class="pane-sub">ALL KEYS DETERMINISTICALLY DERIVED FROM MASTER VAULT</div>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn-pri" onclick="generateNewAddress()">+ New HD Address</button>
          <button id="btnScanHd" class="btn-pri" style="background:#1e2536; border:1px solid var(--border-strong); color:var(--text-secondary);" onclick="scanAndRecoverAccounts()">🔍 Scan &amp; Recover Accounts</button>
        </div>
      </div>
      <div style="flex:1; overflow-y:auto; border:1px solid var(--border-hairline); border-radius:4px; background:var(--bg-card);">
        <table class="ledger-table" style="width:100%; border-collapse:collapse;">
          <thead>
            <tr>
              <th style="width:140px;">Index / Label</th>
              <th>WNX Address</th>
              <th style="width:150px;">Derivation Path</th>
              <th style="width:100px;">State</th>
              <th style="width:140px; text-align:right;">Balance</th>
              <th style="width:150px; text-align:center;">Action</th>
            </tr>
          </thead>
          <tbody id="addressesTableBody">
            <tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">Loading addresses...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 5. Console Pane -->
  <div id="pane-console" class="tab-pane">
    <div id="cliOutput" class="cli-output">WINEX Core Interactive Console v3.6
Type 'help' for available commands.
--------------------------------------------------------------------------------
</div>
    <div class="cli-input-bar">
      <span class="mono" style="color:var(--accent-emerald); margin-right:8px;">winex&gt;</span>
      <input type="text" id="cliInput" class="cli-input" placeholder="Type command (e.g. help, getinfo, balance)..." autocomplete="off" onkeydown="handleCliKey(event)">
    </div>
  </div>

  <!-- 6. Network Pane -->
  <div id="pane-network" class="tab-pane">
    <div class="pane-content">
      <h1 class="pane-h1">Consensus Network &amp; P2P Telemetry</h1>
      <div class="pane-sub">DUAL-PASS SHA-256 SOVEREIGN CONSENSUS</div>
      <div class="mono" style="line-height:2.2; font-size:13px; color:var(--text-secondary);">
        <div>&bull; Gateway Node: <span style="color:#fff;" id="netGateway">https://winexcoin.com (:8081)</span></div>
        <div>&bull; Synchronized Height: <span style="color:var(--accent-cyan);" id="netHeight">#38</span></div>
        <div>&bull; Block Subsidy: <span style="color:var(--accent-green);" id="netReward">40.0000 WNX</span></div>
        <div>&bull; Unmined Pool Remaining: <span style="color:#fff;" id="netPool">10,000,000.00 WNX</span></div>
        <div>&bull; Network Continuity: <span style="color:var(--accent-green);">Immortal P2P Mesh (1+ Active Nodes)</span></div>
      </div>
    </div>
  </div>

  <!-- 7. Preferences Pane -->
  <div id="pane-prefs" class="tab-pane">
    <div class="pane-content">
      <h1 class="pane-h1">Preferences &amp; Security</h1>
      <div class="pane-sub">LOCAL KEYSTORE AND NODE CONFIGURATION</div>
      <div class="mono" style="line-height:2.2; font-size:13px; color:var(--text-secondary);">
        <div>&bull; Interface Theme: <span style="color:#fff;">Dark (Electrum Fintech Default)</span></div>
        <div>&bull; Language: <span style="color:#fff;">English</span></div>
        <div>&bull; Local P2P Node RPC: <span style="color:var(--accent-cyan);">http://127.0.0.1:8081</span></div>
        <div>&bull; Inactivity Auto-Lock: <span style="color:#fff;">15 Minutes</span></div>
      </div>
    </div>
  </div>

  <!-- 8. Specification Pane -->
  <div id="pane-spec" class="tab-pane">
    <div class="pane-content">
      <h1 class="pane-h1">WINEX Core Protocol Specification</h1>
      <div class="pane-sub">AUTONOMOUS LAYER-1 PROOF-OF-WORK SPECIFICATION</div>
      <div class="mono" style="line-height:2; font-size:12px; color:var(--text-secondary); background:var(--bg-card); padding:18px; border-radius:4px;">
Protocol: WINEX (WNX) Sovereign Layer-1 Proof-of-Work
Consensus Algorithm: Dual-Pass SHA-256 Mining Hash Engine
Block Reward: 40.0000 WNX (Halving every 125,000 blocks)
Finite Mineable Supply: 10,000,000.0000 WNX
Genesis Developer Reserve: 2,100,000.0000 WNX (BIP-39 Vault)
Transaction Fees: 0.0000 WNX Zero Protocol Fee
Key Derivation: SECP256k1 + RFC 6979 Deterministic Signatures
Cold Storage: AES-256-GCM Password Encrypted Local Keystore
Architecture: Peer-to-Peer Full Node & Standalone CLI Mining Engine
      </div>
    </div>
  </div>

</div>

<!-- Status Bar -->
<div class="statusbar">
  <div class="sb-left">
    <span class="sb-bal" id="sbBalance">Balance: 0.0000 WNX</span>
    <span class="sb-hide" onclick="toggleBalanceHide()" id="sbHideBtn">Hide</span>
  </div>
  <div class="sb-right">
    <span class="sb-node">Node: P2P Mesh (:8081)</span>
    <span class="sb-meta" id="sbHeight">Height: 0</span>
    <span class="sb-meta">AES-256-GCM</span>
  </div>
</div>

<!-- Onboarding Modal -->
<div id="modalSetup" class="modal-overlay" style="display:none;">
  <div class="modal-card" style="width:460px;">
    <h2 style="font-size:16px; margin-bottom:8px;">WINEX Wallet Setup</h2>
    <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">Create a new keystore or restore an existing 12-word seed. Keys are encrypted locally with AES-256-GCM.</p>
    <textarea id="setupSeed" class="form-input" style="width:100%; height:70px; margin-bottom:10px;" placeholder="12-word seed (generate a new one or paste yours)"></textarea>
    <button class="btn-pri" style="width:100%; margin-bottom:10px;" onclick="genSeed()">Generate New 12-Word Seed</button>
    <input type="password" id="setupPw" class="form-input" style="width:100%; margin-bottom:10px;" placeholder="Choose password (min 4 chars)">
    <button class="btn-pri" style="width:100%;" onclick="finalizeSetup()">Create / Restore Wallet</button>
    <div id="setupErr" style="color:var(--accent-danger); font-size:12px; margin-top:10px;"></div>
  </div>
</div>

<!-- Unlock Modal -->
<div id="modalUnlock" class="modal-overlay" style="display:none;">
  <div class="modal-card" style="width:440px;">
    <h2 style="font-size:16px; margin-bottom:8px;">WINEX Sovereign Vault</h2>
    <p style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">AES-256-GCM cold memory protection active. Enter master password:</p>
    <input type="password" id="modalUnlockPw" class="form-input" style="width:100%; margin-bottom:14px;" placeholder="Vault password" onkeydown="if(event.key==='Enter')doUnlockVault()">
    <div style="display:flex; gap:10px;">
      <button class="btn-pri" style="flex:1;" onclick="doUnlockVault()">Unlock Vault</button>
      <button class="btn-pri" type="button" style="flex:1; background:#1e2536; border:1px solid var(--border-strong); color:var(--text-secondary);" onclick="promptResetKeystore()">New / Reset Wallet</button>
    </div>
    <div id="unlockErr" style="color:var(--accent-danger); font-size:12px; margin-top:10px;"></div>
  </div>
</div>

<script>
const WINEX_TOKEN = '__CSRF_TOKEN__';
const _nativeFetch = window.fetch.bind(window);
window.fetch = function(u, o) {
  o = o || {};
  o.headers = Object.assign({}, o.headers || {}, {'X-WINEX-Token': WINEX_TOKEN});
  return _nativeFetch(u, o);
};
let currentBalance = 0.0;
let currentAddress = "";
let isBalHidden = false;
let allRawBlocks = [];

function toggleMenu(id, e) {
  e.stopPropagation();
  const d = document.getElementById(id);
  const isShown = d.classList.contains('show');
  closeMenus();
  if (!isShown) d.classList.add('show');
}
function closeMenus() {
  document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('show'));
}
window.onclick = closeMenus;

function switchTab(tabId) {
  closeMenus();
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  const btnMap = {'history':0, 'send':1, 'receive':2, 'addresses':3, 'console':4, 'network':5, 'prefs':6, 'spec':7};
  const btns = document.querySelectorAll('.tab-btn');
  if (btns[btnMap[tabId]]) btns[btnMap[tabId]].classList.add('active');

  const pane = document.getElementById('pane-' + tabId);
  if (pane) pane.classList.add('active');
  if (tabId === 'console') setTimeout(() => document.getElementById('cliInput').focus(), 50);
}

function toggleBalanceHide() {
  isBalHidden = !isBalHidden;
  document.getElementById('sbHideBtn').innerText = isBalHidden ? 'Show' : 'Hide';
  renderBalance();
}

function renderBalance() {
  const el = document.getElementById('sbBalance');
  if (isBalHidden) {
    el.innerText = 'Balance: •••••••••••• WNX';
  } else {
    el.innerText = 'Balance: ' + currentBalance.toLocaleString('en-US', {minimumFractionDigits:4, maximumFractionDigits:4}) + ' WNX';
  }
}

async function refreshDashboard() {
  try {
    const resState = await fetch('/api/app_state');
    const dState = await resState.json();
    if (dState.state === 'uninitialized') {
      document.getElementById('modalUnlock').style.display = 'none';
      document.getElementById('modalSetup').style.display = 'flex';
      if (!document.getElementById('setupSeed').value.trim()) {
        genSeed();
      }
      return;
    }
    document.getElementById('modalSetup').style.display = 'none';
    if (dState.state === 'locked') {
      document.getElementById('modalUnlock').style.display = 'flex';
      return;
    } else {
      document.getElementById('modalUnlock').style.display = 'none';
    }

    const resDash = await fetch('/api/info');
    if (resDash.ok) {
      const dash = await resDash.json();
      currentBalance = dash.balance || 0.0;
      currentAddress = dash.address || "";
      renderBalance();

      if (currentAddress) {
        document.getElementById('recvAddressText').innerText = currentAddress;
        document.getElementById('recvQr').src = '/api/wallet/qrcode.png?token=' + WINEX_TOKEN + '&a=' + encodeURIComponent(currentAddress);
      }
      if (dash.accounts) {
        renderAddressesTable(dash.accounts);
        populateSendAccounts(dash.accounts, dash.address);
      }
      document.getElementById('sbHeight').innerText = 'Height: ' + (dash.block_height || 0);
      document.getElementById('netHeight').innerText = '#' + (dash.block_height || 0);
    }

    const resBlocks = await fetch('/api/blocks');
    if (resBlocks.ok) {
      allRawBlocks = await resBlocks.json();
      renderHistoryTable(allRawBlocks);
    }
  } catch(e) {
    console.error("Dashboard refresh err:", e);
  }
}

function renderHistoryTable(blocks) {
  const body = document.getElementById('historyBody');
  if (!blocks || !Array.isArray(blocks) || blocks.length === 0) {
    body.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:32px; color:var(--text-muted);">No blocks recorded in ledger.</td></tr>';
    return;
  }

  // Strictly sort by timestamp descending (newest on top)
  const sortedBlocks = [...blocks].sort((a, b) => {
    const tA = Number(a.timestamp) || 0;
    const tB = Number(b.timestamp) || 0;
    if (tB !== tA) return tB - tA;
    const iA = Number(a.block_index || a.index) || 0;
    const iB = Number(b.block_index || b.index) || 0;
    return iB - iA;
  });

  let html = '';
  sortedBlocks.forEach(b => {
    const idx = b.block_index || b.index || 0;
    if (idx === 0) return; // Skip Block #0
    let miner = (b.miner || '').trim();
    if (!miner) miner = 'WNX8D4B5CED15F50A144899A8B3551C8CD4';
    const shortMiner = miner.length > 16 ? miner.substring(0, 14) + '...' : miner;
    let reward = b.reward;
    if (!reward || reward <= 0) reward = 40.0;

    let timeStr = '-';
    if (b.timestamp) {
      const dt = new Date(b.timestamp * 1000);
      timeStr = dt.toISOString().replace('T', ' ').substring(0, 19);
    }

    html += '<tr>' +
      '<td class="cell-state">Mined</td>' +
      '<td class="cell-ref">Block #' + idx + ' mined by ' + shortMiner + '</td>' +
      '<td class="cell-value">+' + reward.toFixed(4) + ' WNX</td>' +
      '<td class="cell-time">' + timeStr + '</td>' +
      '</tr>';
  });
  body.innerHTML = html;
}

function filterHistoryTable() {
  const q = document.getElementById('filterInput').value.trim().toLowerCase();
  if (!q) {
    renderHistoryTable(allRawBlocks);
    return;
  }
  const filtered = allRawBlocks.filter(b => {
    const idx = (b.block_index || b.index || '').toString();
    const miner = (b.miner || '').toLowerCase();
    const hash = (b.hash || '').toLowerCase();
    return idx.includes(q) || miner.includes(q) || hash.includes(q);
  });
  renderHistoryTable(filtered);
}

function copyCurrentAddress() {
  if (currentAddress) {
    navigator.clipboard.writeText(currentAddress);
    alert("Copied receiving address to clipboard:\n" + currentAddress);
  }
}

function populateSendAccounts(accounts, activeAddr) {
  const sel = document.getElementById('sendSourceAccount');
  if (!sel || !accounts || !Array.isArray(accounts)) return;
  const currentVal = sel.value;
  sel.innerHTML = '';
  accounts.forEach(acc => {
    const opt = document.createElement('option');
    opt.value = acc.address;
    opt.dataset.balance = acc.balance || 0.0;
    const shortAddr = acc.address.length > 16 ? (acc.address.substring(0, 8) + '...' + acc.address.substring(acc.address.length - 6)) : acc.address;
    opt.innerText = '#' + acc.index + ' ' + (acc.label || ('Account #' + acc.index)) + ' [' + shortAddr + '] — ' + Number(acc.balance || 0).toFixed(4) + ' WNX';
    if (currentVal && opt.value === currentVal) {
      opt.selected = true;
    } else if (!currentVal && acc.address === activeAddr) {
      opt.selected = true;
    }
    sel.appendChild(opt);
  });
  updateSendAccountBal();
}

function updateSendAccountBal() {
  const sel = document.getElementById('sendSourceAccount');
  const lbl = document.getElementById('sendAvailableBal');
  if (!sel || !lbl) return;
  const opt = sel.options[sel.selectedIndex];
  const bal = opt ? parseFloat(opt.dataset.balance || 0) : 0;
  lbl.innerText = 'Available: ' + bal.toFixed(4) + ' WNX (Use Max)';
}

function setSendMaxAmount() {
  const sel = document.getElementById('sendSourceAccount');
  const inp = document.getElementById('inpAmount');
  if (!sel || !inp) return;
  const opt = sel.options[sel.selectedIndex];
  const bal = opt ? parseFloat(opt.dataset.balance || 0) : 0;
  inp.value = bal.toFixed(4);
}

async function doSendTransaction() {
  const sel = document.getElementById('sendSourceAccount');
  const fromAddr = sel ? sel.value : '';
  const recip = document.getElementById('inpRecipient').value.trim();
  const amt = parseFloat(document.getElementById('inpAmount').value);
  const out = document.getElementById('sendResult');

  if (!recip) {
    out.innerText = "Error: Please enter destination WNX address.";
    out.style.color = "var(--accent-danger)";
    return;
  }
  if (isNaN(amt) || amt <= 0) {
    out.innerText = "Error: Please enter a valid transfer amount.";
    out.style.color = "var(--accent-danger)";
    return;
  }

  out.innerText = "Signing & broadcasting across P2P mesh...";
  out.style.color = "var(--text-main)";

  try {
    const res = await fetch('/api/wallet/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({from_address: fromAddr, recipient: recip, amount: amt})
    });
    const d = await res.json();
    if (res.ok && (d.status === 'ok' || d.success || d.tx_id)) {
      out.innerText = "Transaction Broadcast Confirmed (0.0000 WNX Fee) • TXID: " + (d.tx_id || 'Accepted');
      out.style.color = "var(--accent-green)";
      document.getElementById('inpRecipient').value = '';
      refreshDashboard();
    } else {
      out.innerText = "Rejected: " + (d.detail || d.message || JSON.stringify(d));
      out.style.color = "var(--accent-danger)";
    }
  } catch(e) {
    out.innerText = "Broadcast error: " + e.message;
    out.style.color = "var(--accent-danger)";
  }
}

async function genSeed() {
  const r = await fetch('/api/onboarding/generate_seed');
  const d = await r.json();
  document.getElementById('setupSeed').value = d.seed || '';
  document.getElementById('setupErr').innerText = 'Write these words down. They are the only way to recover your funds.';
}
async function finalizeSetup() {
  const seed = document.getElementById('setupSeed').value.trim();
  const pw = document.getElementById('setupPw').value;
  const r = await fetch('/api/onboarding/finalize_setup', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({seed: seed, password: pw})});
  if (r.ok) {
    document.getElementById('modalSetup').style.display = 'none';
    refreshDashboard();
  } else {
    document.getElementById('setupErr').innerText = await r.text();
  }
}

async function promptResetKeystore() {
  if (!confirm("WARNING: Starting fresh or resetting will wipe the current local vault on this machine.\n\nEnsure you have backed up any existing 12-word recovery seed phrase.\n\nDo you want to proceed and create a fresh wallet?")) {
    return;
  }
  try {
    const res = await fetch('/api/vault/wipe_and_reset', {method: 'POST'});
    if (res.ok) {
      document.getElementById('modalUnlock').style.display = 'none';
      document.getElementById('modalUnlockPw').value = '';
      document.getElementById('unlockErr').innerText = '';
      document.getElementById('setupSeed').value = '';
      document.getElementById('setupPw').value = '';
      document.getElementById('setupErr').innerText = '';
      document.getElementById('modalSetup').style.display = 'flex';
      await genSeed();
    } else {
      alert("Failed to reset keystore.");
    }
  } catch(e) {
    alert("Error resetting keystore: " + e.message);
  }
}

async function doUnlockVault() {
  const pw = document.getElementById('modalUnlockPw').value;
  const res = await fetch('/api/vault/unlock', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pw})
  });
  if (res.ok) {
    document.getElementById('modalUnlockPw').value = '';
    document.getElementById('modalUnlock').style.display = 'none';
    refreshDashboard();
  } else {
    document.getElementById('unlockErr').innerText = "Incorrect vault password.";
  }
}

async function lockVault() {
  await fetch('/api/vault/lock', {method: 'POST'});
  document.getElementById('modalUnlock').style.display = 'flex';
}

async function promptBackupSeed() {
  const pw = prompt("Enter vault password to reveal 12-word recovery seed:");
  if (!pw) return;
  const res = await fetch('/api/settings/export_seed', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pw})
  });
  if (res.ok) {
    const d = await res.json();
    alert("YOUR 12-WORD MASTER SEED:\n\n" + d.seed_phrase + "\n\nNever share these words with anyone.");
  } else {
    alert("Incorrect password.");
  }
}

async function handleCliKey(e) {
  if (e.key !== 'Enter') return;
  const inp = document.getElementById('cliInput');
  const cmd = inp.value.trim();
  inp.value = '';
  if (!cmd) return;

  const out = document.getElementById('cliOutput');
  out.innerText += "winex> " + cmd + "\n";
  if (cmd.toLowerCase() === 'clear') { out.innerText = ''; return; }

  try {
    const res = await fetch('/api/cli/execute', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({command: cmd})
    });
    const d = await res.json();
    out.innerText += (d.output || JSON.stringify(d)) + "\n\n";
    out.scrollTop = out.scrollHeight;
  } catch(err) {
    out.innerText += "Execution error: " + err.message + "\n\n";
  }
}

function copyAddrText(addr) {
  if (addr) {
    navigator.clipboard.writeText(addr);
    alert("Copied WNX address to clipboard:\n" + addr);
  }
}

function renderAddressesTable(accounts) {
  const tbody = document.getElementById('addressesTableBody');
  if (!tbody) return;
  if (!accounts || !Array.isArray(accounts) || accounts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">No derived addresses found.</td></tr>';
    return;
  }
  let html = '';
  accounts.forEach(acc => {
    const isAct = !!acc.is_active;
    const bal = Number(acc.balance) || 0.0;
    const deriv = acc.derivation || ("m/44'/999'/0'/0/" + acc.index);
    const fullAddr = acc.address || '';
    
    html += '<tr style="border-bottom:1px solid var(--border-hairline);">' +
      '<td style="padding:10px 14px; font-weight:600;">#' + acc.index + ' ' + (acc.label || ('Account #' + acc.index)) + '</td>' +
      '<td style="padding:10px 14px; font-family:\'JetBrains Mono\', monospace; font-size:12px; color:' + (isAct ? '#fff' : 'var(--text-secondary)') + ';">' + fullAddr + '</td>' +
      '<td style="padding:10px 14px; font-family:\'JetBrains Mono\', monospace; font-size:11px; color:var(--text-muted);">' + deriv + '</td>' +
      '<td style="padding:10px 14px;"><span style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; font-weight:600; ' + (isAct ? 'background:rgba(34,197,94,0.15); color:var(--accent-green);' : 'background:rgba(148,163,184,0.1); color:var(--text-muted);') + '">' + (isAct ? 'Receiving' : 'Derived') + '</span></td>' +
      '<td style="padding:10px 14px; text-align:right; font-family:\'JetBrains Mono\', monospace; font-weight:bold; color:' + (bal > 0 ? 'var(--accent-green)' : 'var(--text-muted)') + ';">' + bal.toFixed(4) + ' WNX</td>' +
      '<td style="padding:10px 14px; text-align:center;">' +
        '<button onclick="copyAddrText(\'' + fullAddr + '\')" class="btn-pri" style="padding:2px 8px; font-size:11px; background:#1e2536; border:1px solid var(--border-strong); margin-right:6px;">Copy</button>' +
        (isAct ? '<span style="font-size:11px; font-weight:600; color:var(--accent-green);">Active</span>' : '<button onclick="setActiveAccount(' + acc.index + ')" class="btn-pri" style="padding:2px 8px; font-size:11px;">Set Active</button>') +
      '</td>' +
      '</tr>';
  });
  tbody.innerHTML = html;
}

async function setActiveAccount(idx) {
  try {
    const res = await fetch('/api/wallet/set_active', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({index: idx})
    });
    if (res.ok) {
      refreshDashboard();
    }
  } catch(e) {
    alert("Error setting active account: " + e.message);
  }
}

async function generateNewAddress() {
  try {
    const res = await fetch('/api/wallet/new_address', {method: 'POST'});
    if (res.ok) {
      refreshDashboard();
    }
  } catch(e) {
    alert("Error creating new HD address: " + e.message);
  }
}

async function scanAndRecoverAccounts() {
  const btn = document.getElementById('btnScanHd');
  const prevText = btn ? btn.innerText : '';
  if (btn) btn.innerText = "Scanning Blockchain...";
  try {
    const res = await fetch('/api/wallet/scan_accounts', {method: 'POST'});
    if (res.ok) {
      const d = await res.json();
      await refreshDashboard();
      alert("Account Recovery Scan Complete:\n" + (d.discovered > 0 ? ("Successfully recovered " + d.discovered + " account(s) with history/balance.") : "All active derived accounts are already synced."));
    }
  } catch(e) {
    alert("Scan error: " + e.message);
  } finally {
    if (btn) btn.innerText = prevText;
  }
}

refreshDashboard();
setInterval(refreshDashboard, 2500);
</script>
</body>
</html>`
