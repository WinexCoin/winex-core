package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func isPrivateOrMetadataIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.169.254 (Cloud metadata) and link local
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.64.0.0/10 (Carrier grade NAT)
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return true
		}
	}
	return false
}

// IsSafeMinerEndpoint validates endpoint scheme, hostname, and resolved IP
func IsSafeMinerEndpoint(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	// Allow loopback for local node mining
	host := u.Hostname()
	if host == "127.0.0.1" || host == "localhost" {
		return u.Scheme == "http" || u.Scheme == "https"
	}
	// Remote nodes MUST use HTTPS
	if u.Scheme != "https" {
		return false
	}
	// Prevent local domains
	hLower := strings.ToLower(host)
	if strings.HasSuffix(hLower, ".local") || strings.HasSuffix(hLower, ".internal") || strings.HasSuffix(hLower, ".onion") {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return !isPrivateOrMetadataIP(ip)
	}
	// Resolve DNS and check all IPs
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, rip := range ips {
		if isPrivateOrMetadataIP(rip) {
			return false
		}
	}
	return true
}

func newSafeMinerHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			if host == "127.0.0.1" || host == "::1" {
				return nil
			}
			ip := net.ParseIP(host)
			if ip != nil && isPrivateOrMetadataIP(ip) {
				return errors.New("SSRF protection: prohibited private/metadata IP")
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
			if host == "127.0.0.1" || host == "localhost" {
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isPrivateOrMetadataIP(ip.IP) {
					return nil, fmt.Errorf("SSRF protection: host %s resolved to prohibited IP %s", host, ip.IP.String())
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			// Enforce HTTPS on redirects and re-verify endpoint
			if req.URL.Scheme != "https" && req.URL.Hostname() != "127.0.0.1" && req.URL.Hostname() != "localhost" {
				return errors.New("HTTP redirect prohibited (must remain HTTPS)")
			}
			if !IsSafeMinerEndpoint(req.URL.String()) {
				return errors.New("redirect to prohibited host/IP blocked")
			}
			return nil
		},
	}
}

type MiningTemplate struct {
	BlockIndex  int64   `json:"block_index"`
	PrevHash    string  `json:"prev_hash"`
	MerkleRoot  string  `json:"merkle_root"`
	Difficulty  int     `json:"difficulty"`
	Target      string  `json:"target"`
	BlockReward float64 `json:"block_reward"`
	PoolBalance float64 `json:"pool_remaining"`
	ServerTime  float64 `json:"server_time"`
}

var globalClockSkew atomic.Value

func getNetworkTimestamp() float64 {
	nowSec := float64(time.Now().UnixNano()) / 1e9
	if s, ok := globalClockSkew.Load().(float64); ok {
		return nowSec + s
	}
	return nowSec
}

type SubmitPayload struct {
	MinerAddress string  `json:"miner_address"`
	BlockIndex   int64   `json:"block_index"`
	Nonce        int64   `json:"nonce"`
	Timestamp    float64 `json:"timestamp"`
	Hash         string  `json:"hash"`
	ReportedHash string  `json:"reported_hash"`
}

type PeerDiscoveryResponse struct {
	Peers []string `json:"peers"`
}

type MeshManager struct {
	mu    sync.RWMutex
	nodes []string
}

func NewMeshManager(seedNodes []string) *MeshManager {
	mm := &MeshManager{nodes: seedNodes}
	return mm
}

func (mm *MeshManager) GetNodes() []string {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	copied := make([]string, len(mm.nodes))
	copy(copied, mm.nodes)
	return copied
}

func (mm *MeshManager) DiscoverPeers(client *http.Client) {
	discovered := make(map[string]bool)
	mm.mu.RLock()
	for _, n := range mm.nodes {
		discovered[n] = true
	}
	mm.mu.RUnlock()

	for _, n := range mm.GetNodes() {
		reqURL := fmt.Sprintf("%s/api/p2p/peers", n)
		resp, err := client.Get(reqURL)
		if err != nil {
			reqURL = fmt.Sprintf("%s/p2p/peers", n)
			resp, err = client.Get(reqURL)
		}
		if err != nil {
			continue
		}
		var pResp PeerDiscoveryResponse
		dec := json.NewDecoder(io.LimitReader(resp.Body, 65536))
		if err := dec.Decode(&pResp); err == nil {
			for _, p := range pResp.Peers {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
					p = "https://" + p
				}
				if IsSafeMinerEndpoint(p) && len(discovered) < 100 {
					discovered[p] = true
				}
			}
		}
		resp.Body.Close()
	}

	mm.mu.Lock()
	newList := make([]string, 0, len(discovered))
	for p := range discovered {
		newList = append(newList, p)
	}
	mm.nodes = newList
	mm.mu.Unlock()
}

func (mm *MeshManager) FetchTemplate(client *http.Client) (*MiningTemplate, string, error) {
	for _, nodeURL := range mm.GetNodes() {
		reqURL := fmt.Sprintf("%s/api/mining/template", nodeURL)
		resp, err := client.Get(reqURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			var tmpl MiningTemplate
			dec := json.NewDecoder(resp.Body)
			if err := dec.Decode(&tmpl); err == nil && tmpl.BlockIndex > 0 {
				resp.Body.Close()
				return &tmpl, nodeURL, nil
			}
		}
		resp.Body.Close()
	}
	return nil, "", fmt.Errorf("no validator template available from peer mesh")
}

func (mm *MeshManager) BroadcastSolvedBlock(client *http.Client, payload SubmitPayload) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}

	nodes := mm.GetNodes()
	// Prefer primary network gateway first
	primaryNode := "https://winexcoin.com"
	var otherNodes []string
	for _, n := range nodes {
		if strings.Contains(n, "winexcoin.com") {
			primaryNode = n
		} else {
			otherNodes = append(otherNodes, n)
		}
	}

	// Submit to primary gateway
	submitURL := fmt.Sprintf("%s/api/mining/submit", primaryNode)
	req, err := http.NewRequest("POST", submitURL, bytes.NewBuffer(b))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			resBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()
			bodyStr := strings.TrimSpace(string(resBody))
			if resp.StatusCode == 200 && (strings.Contains(bodyStr, `"success":true`) || strings.Contains(bodyStr, `"status":"ok"`)) {
				fmt.Printf("\n \033[38;2;16;185;129m[ACCEPTED]\033[0m Block #%d successfully verified by %s: %s\n", payload.BlockIndex, primaryNode, bodyStr)
			} else {
				fmt.Printf("\n \033[38;2;239;68;68m[REJECTED]\033[0m Block #%d rejected by %s (Status %d): %s\n", payload.BlockIndex, primaryNode, resp.StatusCode, bodyStr)
			}
		}
	}

	// Relay asynchronously to local/secondary peers
	for _, endpoint := range otherNodes {
		go func(ep string) {
			sURL := fmt.Sprintf("%s/api/mining/submit", ep)
			r, e := http.NewRequest("POST", sURL, bytes.NewBuffer(b))
			if e == nil {
				r.Header.Set("Content-Type", "application/json")
				res, e2 := client.Do(r)
				if e2 == nil {
					res.Body.Close()
				}
			}
		}(endpoint)
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

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func printBanner(activeEngine, intensityLabel string) {
	fmt.Print("\033[38;2;99;102;241m")
	fmt.Println(`  ╔══════════════════════════════════════════════════════════════════════════╗`)
	fmt.Println(`  ║       WINEX CORE // HYBRID PROOF-OF-WORK CONSENSUS ENGINE v3.6.0         ║`)
	fmt.Println(`  ║    Deterministic SHA-256 Mining • Autonomous Sovereign Layer-1 Mesh      ║`)
	fmt.Println(`  ╚══════════════════════════════════════════════════════════════════════════╝`)
	fmt.Print("\033[0m")
	fmt.Printf("  \033[38;2;56;189;248m[HARDWARE]\033[0m  Engine: %s\n", activeEngine)
	fmt.Printf("  \033[38;2;245;158;11m[INTENSITY]\033[0m Mode:   %s\n", intensityLabel)
	fmt.Printf("  \033[38;2;16;185;129m[ENDPOINT]\033[0m  Node:   https://winexcoin.com (Cloudflare Protected)\n")
	fmt.Printf("  \033[38;2;148;163;184m[CONTACT]\033[0m   Email:  support@winexcoin.com\n")
	fmt.Printf("  \033[38;2;156;163;175m[LEGAL]\033[0m     Non-custodial open-source PoW software - Not a financial/forex product\n")
	fmt.Printf("  \033[38;2;239;68;68m[NOTICE]\033[0m    Zero affiliation with unauthorized entities (e.g. 'Winex Markets' forex)\n")
	fmt.Println("  ──────────────────────────────────────────────────────────────────────────")
}

func resolveWorkersAndEngine(deviceFlag string, intensityFlag int, cliWorkers int) (string, string, int, bool, int) {
	totalCores := runtime.NumCPU()
	if totalCores < 1 {
		totalCores = 1
	}

	hasGPU, gpuName := detectGPUHardware()
	nativeGPU, nativeName := IsNativeGPUAvailable()
	if nativeGPU && nativeName != "" {
		hasGPU = true
		gpuName = nativeName
	}

	deviceChoice := strings.ToLower(strings.TrimSpace(deviceFlag))
	var isGPU bool
	var activeEngine string

	if deviceChoice == "gpu" {
		if hasGPU {
			isGPU = true
		} else {
			fmt.Println("\n \033[38;2;245;158;11m[FALLBACK]\033[0m No compatible GPU driver found; falling back to Multi-Core CPU Engine.")
			isGPU = false
		}
	} else if deviceChoice == "cpu" {
		isGPU = false
	} else if cliWorkers > 0 || intensityFlag > 0 {
		if hasGPU {
			isGPU = true
		} else {
			isGPU = false
		}
	} else {
		// Interactive Selection Menu
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("\n \033[1;36m[HARDWARE ACCELERATION ENGINE SELECTION]\033[0m")
		if hasGPU {
			fmt.Printf("  [1] GPU Turbo Accelerator Mode (%s - 100%% Dedicated GPU Compute)\n", gpuName)
			fmt.Println("  [2] CPU Multi-Threaded Engine (Optimized AVX Goroutines)")
			fmt.Print(" Select hardware engine [1-2] (default: 1): ")
			if scanner.Scan() {
				choice := strings.TrimSpace(scanner.Text())
				if choice == "2" {
					isGPU = false
				} else {
					isGPU = true
				}
			} else {
				isGPU = true
			}
		} else {
			fmt.Println("  [1] Pure-Go Multi-Core CPU Engine (Optimized AVX Goroutines)")
			fmt.Print(" Select hardware engine [1] (default: 1): ")
			if scanner.Scan() {
				// default
			}
			isGPU = false
		}
	}

	if isGPU {
		activeEngine = fmt.Sprintf("GPU Turbo Accelerator (%s)", gpuName)
	} else {
		activeEngine = fmt.Sprintf("Pure-Go Multi-Core AVX Engine (%d Threads)", totalCores)
	}

	var workers int
	var intensityLabel string
	selectedIntensity := 4

	if intensityFlag >= 1 && intensityFlag <= 4 {
		selectedIntensity = intensityFlag
	} else if cliWorkers == 0 {
		// Interactive Intensity Prompt
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("\n \033[1;36m[RESOURCE ALLOCATION / INTENSITY PROFILE]\033[0m")
		if isGPU {
			fmt.Printf("  Dedicated GPU Accelerator: %s\n", gpuName)
			fmt.Println("  [1] Eco / Low Intensity      (25% GPU Power - Quiet background mining)")
			fmt.Println("  [2] Balanced / Medium        (50% GPU Power - Optimal for everyday use)")
			fmt.Println("  [3] High Performance         (75% GPU Power - Dedicated high-throughput)")
			fmt.Println("  [4] Turbo / Maximum Output   (100% GPU Power - Full hardware capacity)")
		} else {
			fmt.Printf("  Detected system cores: %d logical threads\n", totalCores)
			fmt.Println("  [1] Eco / Low Intensity      (25% CPU Cores - Quiet background mining)")
			fmt.Println("  [2] Balanced / Medium        (50% CPU Cores - Optimal for everyday use)")
			fmt.Println("  [3] High Performance         (75% CPU Cores - Dedicated high-throughput)")
			fmt.Println("  [4] Turbo / Maximum Output   (100% CPU Cores - Full hardware capacity)")
		}
		fmt.Print(" Select intensity profile [1-4] (default: 4): ")
		if scanner.Scan() {
			txt := strings.TrimSpace(scanner.Text())
			if val, err := strconv.Atoi(txt); err == nil && val >= 1 && val <= 4 {
				selectedIntensity = val
			}
		}
	}

	if isGPU {
		workers = 1
		switch selectedIntensity {
		case 1:
			intensityLabel = "Eco / Low Intensity (25% GPU Power)"
		case 2:
			intensityLabel = "Balanced / Medium (50% GPU Power)"
		case 3:
			intensityLabel = "High Performance (75% GPU Power)"
		case 4:
			intensityLabel = "Turbo / Maximum Output (100% Dedicated GPU Compute)"
		}
	} else {
		if cliWorkers > 0 {
			workers = cliWorkers
			intensityLabel = fmt.Sprintf("Custom Override (%d Threads)", workers)
		} else {
			switch selectedIntensity {
			case 1:
				workers = int(math.Max(1, float64(totalCores)/4.0))
				intensityLabel = fmt.Sprintf("Eco / Low Intensity (25%% Power - %d Threads)", workers)
			case 2:
				workers = int(math.Max(1, float64(totalCores)/2.0))
				intensityLabel = fmt.Sprintf("Balanced / Medium (50%% Power - %d Threads)", workers)
			case 3:
				workers = int(math.Max(1, float64(totalCores)*0.75))
				intensityLabel = fmt.Sprintf("High Performance (75%% Power - %d Threads)", workers)
			case 4:
				workers = totalCores
				intensityLabel = fmt.Sprintf("Turbo / Maximum Output (100%% Power - %d Cores)", workers)
			}
		}
	}

	if workers < 1 {
		workers = 1
	}

	return activeEngine, intensityLabel, workers, isGPU, selectedIntensity
}

func main() {
	initTerminalEnv()

	var minerAddr string
	var deviceFlag string
	var intensityFlag int
	var cliWorkers int
	var nodeFlag string

	flag.StringVar(&minerAddr, "address", "", "Recipient wallet address for block rewards (WNX...)")
	flag.StringVar(&deviceFlag, "device", "auto", "Hardware compute device: auto | gpu | cpu")
	flag.IntVar(&intensityFlag, "intensity", 0, "Intensity profile: 1 (Eco 25%), 2 (Balanced 50%), 3 (High 75%), 4 (Turbo 100%)")
	flag.IntVar(&cliWorkers, "threads", 0, "Validation worker thread override count")
	flag.StringVar(&nodeFlag, "node", "", "Initial consensus node URL override")
	flag.Parse()

	clearScreen()

	scanner := bufio.NewScanner(os.Stdin)
	for strings.TrimSpace(minerAddr) == "" {
		fmt.Println("\n \033[1;36m[WINEX WALLET SETUP]\033[0m")
		fmt.Print(" Enter your WINEX payout wallet address (WNX...): ")
		if scanner.Scan() {
			minerAddr = strings.TrimSpace(scanner.Text())
		}
		if !strings.HasPrefix(minerAddr, "WNX") || len(minerAddr) < 20 {
			fmt.Println(" \033[1;31m[ERROR] Invalid address. WINEX addresses must begin with 'WNX' (min 20 chars).\033[0m")
			minerAddr = ""
		}
	}

	activeEngine, intensityLabel, activeWorkers, isGPU, intensityLevel := resolveWorkersAndEngine(deviceFlag, intensityFlag, cliWorkers)

	clearScreen()
	printBanner(activeEngine, intensityLabel)

	seedNodes := []string{
		"http://127.0.0.1:8081",
		"https://winexcoin.com",
	}
	if nodeFlag != "" {
		if !IsSafeMinerEndpoint(nodeFlag) {
			fmt.Printf("\n \033[38;2;239;68;68m[FATAL ERROR]\033[0m Invalid or unsafe node URL: %s (Must be loopback or public HTTPS)\n", nodeFlag)
			os.Exit(1)
		}
		seedNodes = append([]string{nodeFlag}, seedNodes...)
	}

	mm := NewMeshManager(seedNodes)
	httpClient := newSafeMinerHTTPClient(8 * time.Second)

	var totalHashes uint64
	var totalSolved uint64
	var currentBlockIndex int64

	fmt.Printf("\n \033[38;2;16;185;129m[ONLINE]\033[0m Connected to WINEX L1 Mesh Network\n")
	if isGPU {
		fmt.Printf(" \033[38;2;99;102;241m[ENGINE]\033[0m Dedicated GPU Compute Engine: %s (100%% Dedicated GPU)\n", activeEngine)
	} else {
		fmt.Printf(" \033[38;2;99;102;241m[ENGINE]\033[0m Active Compute Workers: %d parallel CPU goroutines\n", activeWorkers)
	}
	fmt.Printf(" \033[38;2;148;163;184m[PAYOUT]\033[0m Reward Beneficiary: %s\n\n", minerAddr)

	go func() {
		for {
			mm.DiscoverPeers(httpClient)
			time.Sleep(30 * time.Second)
		}
	}()

	var currentTmpl *MiningTemplate
	var tmplMu sync.RWMutex
	var currentEpoch uint64
	var lastSubmittedBlock int64
	var blockStartUnixNano atomic.Int64
	blockStartUnixNano.Store(time.Now().UnixNano())
	globalClockSkew.Store(float64(0.0))
	triggerUpdate := make(chan struct{}, 1)

	go func() {
		for {
			tmpl, activeNode, err := mm.FetchTemplate(httpClient)
			if err == nil && tmpl != nil {
				if tmpl.ServerTime > 0 {
					nowSec := float64(time.Now().UnixNano()) / 1e9
					globalClockSkew.Store(tmpl.ServerTime - nowSec)
				}
				tmplMu.Lock()
				if currentTmpl == nil || tmpl.BlockIndex != currentTmpl.BlockIndex || tmpl.PrevHash != currentTmpl.PrevHash {
					currentTmpl = tmpl
					atomic.StoreInt64(&currentBlockIndex, tmpl.BlockIndex)
					atomic.StoreInt64(&lastSubmittedBlock, tmpl.BlockIndex-1)
					atomic.AddUint64(&currentEpoch, 1)
					blockStartUnixNano.Store(time.Now().UnixNano())

					fmt.Printf(" \033[38;2;56;189;248m[BLOCK-TEMPLATE]\033[0m Height #%d | PrevHash: %s... | Target: %s... (via %s)\n",
						tmpl.BlockIndex, tmpl.PrevHash[:16], tmpl.Target[:16], activeNode)
				}
				tmplMu.Unlock()
			}
			select {
			case <-time.After(2500 * time.Millisecond):
			case <-triggerUpdate:
			}
		}
	}()

	time.Sleep(1 * time.Second)

	if isGPU {
		// Launch 100% Dedicated GPU Compute Pipeline
		go func() {
			var currentNonce uint64 = uint64(time.Now().UnixNano())
			batchSize := uint32(4194304)
			var sleepDuration time.Duration = 0
			switch intensityLevel {
			case 1:
				batchSize = 2097152
				sleepDuration = 15 * time.Millisecond
			case 2:
				batchSize = 4194304
				sleepDuration = 10 * time.Millisecond
			case 3:
				batchSize = 4194304
				sleepDuration = 2 * time.Millisecond
			case 4:
				batchSize = 4194304
				sleepDuration = 0
			}

			for {
				tmplMu.RLock()
				tmpl := currentTmpl
				myEpoch := atomic.LoadUint64(&currentEpoch)
				tmplMu.RUnlock()

				if tmpl == nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}

				targetHex := tmpl.Target
				if targetHex == "" {
					targetHex = "0000007fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				}

				blockTimestamp := getNetworkTimestamp()
				prefixStr := fmt.Sprintf("%d:%s:%s:%s:%.4f:", tmpl.BlockIndex, tmpl.PrevHash, tmpl.MerkleRoot, minerAddr, blockTimestamp)
				saltPrefix := prefixStr
				if len(saltPrefix) > 16 {
					saltPrefix = saltPrefix[:16]
				}
				hSalt := sha256.Sum256([]byte(minerAddr + saltPrefix))
				saltHex := hex.EncodeToString(hSalt[:])

				if !ValidateMiningJobInputs(prefixStr, saltHex, targetHex) {
					time.Sleep(50 * time.Millisecond)
					continue
				}

				found, solvedNonce, solvedHash := RunGPUBatch(prefixStr, saltHex, targetHex, currentNonce, batchSize)
				atomic.AddUint64(&totalHashes, uint64(batchSize))
				currentNonce += uint64(batchSize)

				if found {
					if atomic.CompareAndSwapInt64(&lastSubmittedBlock, tmpl.BlockIndex-1, tmpl.BlockIndex) {
						atomic.AddUint64(&totalSolved, 1)
						atomic.AddUint64(&currentEpoch, 1)

						fmt.Printf("\n\n \033[38;2;16;185;129m[SOLVED]\033[0m GPU BLOCK #%d SOLUTION FOUND | Nonce: %d | Hash: %s\n", tmpl.BlockIndex, solvedNonce, solvedHash)
						fmt.Printf(" \033[38;2;56;189;248m[RELAY]\033[0m  Broadcasting candidate across P2P consensus mesh...\n")

						payload := SubmitPayload{
							MinerAddress: minerAddr,
							BlockIndex:   tmpl.BlockIndex,
							Nonce:        int64(solvedNonce),
							Timestamp:    blockTimestamp,
							Hash:         solvedHash,
							ReportedHash: solvedHash,
						}
						mm.BroadcastSolvedBlock(httpClient, payload)

						select {
						case triggerUpdate <- struct{}{}:
						default:
						}
					}
					currentNonce = uint64(time.Now().UnixNano())
				}

				if atomic.LoadUint64(&currentEpoch) != myEpoch {
					currentNonce = uint64(time.Now().UnixNano())
				}

				if sleepDuration > 0 {
					time.Sleep(sleepDuration)
				}
			}
		}()
	} else {
		// Launch parallel CPU workers with zero-allocation inner hashing
		for wID := 0; wID < activeWorkers; wID++ {
			go func(id int) {
				for {
					tmplMu.RLock()
					tmpl := currentTmpl
					myEpoch := atomic.LoadUint64(&currentEpoch)
					tmplMu.RUnlock()

					if tmpl == nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}

					targetHex := tmpl.Target
					if targetHex == "" {
						targetHex = "0000007fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
					}
					targetBytes := []byte(targetHex)

					startNonce := int64(id) * 250000000
					endNonce := int64(id+1) * 250000000
					blockTimestamp := getNetworkTimestamp()

					// Zero-allocation pre-computations:
					prefixStr := fmt.Sprintf("%d:%s:%s:%s:%.4f:", tmpl.BlockIndex, tmpl.PrevHash, tmpl.MerkleRoot, minerAddr, blockTimestamp)
					prefixBytes := []byte(prefixStr)

					saltPrefix := prefixStr
					if len(saltPrefix) > 16 {
						saltPrefix = saltPrefix[:16]
					}
					hSalt := sha256.Sum256([]byte(minerAddr + saltPrefix))
					var saltHex [64]byte
					hex.Encode(saltHex[:], hSalt[:])

					if !ValidateMiningJobInputs(prefixStr, string(saltHex[:]), targetHex) {
						time.Sleep(100 * time.Millisecond)
						continue
					}

					var buf [384]byte
					copy(buf[:], prefixBytes)
					pLen := len(prefixBytes)

					var h1Hex [64]byte
					var combined [128]byte
					copy(combined[64:128], saltHex[:])
					var h2Hex [64]byte

					for n := startNonce; n < endNonce; n++ {
						if (n & 1023) == 0 {
							if atomic.LoadUint64(&currentEpoch) != myEpoch {
								break
							}
						}

						// Append nonce directly into preallocated buffer
						nonceBytes := strconv.AppendInt(buf[pLen:pLen], n, 10)
						totLen := pLen + len(nonceBytes)

						// Pass 1: SHA256 of raw template
						h1 := sha256.Sum256(buf[:totLen])
						hex.Encode(h1Hex[:], h1[:])

						// Pass 2: SHA256(h1Hex + saltHex)
						copy(combined[0:64], h1Hex[:])
						h2 := sha256.Sum256(combined[:])
						hex.Encode(h2Hex[:], h2[:])

						atomic.AddUint64(&totalHashes, 1)

						// Target comparison
						if bytes.Compare(h2Hex[:], targetBytes) <= 0 {
							solvedHash := string(h2Hex[:])
							if atomic.CompareAndSwapInt64(&lastSubmittedBlock, tmpl.BlockIndex-1, tmpl.BlockIndex) {
								atomic.AddUint64(&totalSolved, 1)
								atomic.AddUint64(&currentEpoch, 1)

								fmt.Printf("\n\n \033[38;2;16;185;129m[SOLVED]\033[0m BLOCK #%d SOLUTION FOUND | Nonce: %d | Hash: %s\n", tmpl.BlockIndex, n, solvedHash)
								fmt.Printf(" \033[38;2;56;189;248m[RELAY]\033[0m  Broadcasting candidate across P2P consensus mesh...\n")

								payload := SubmitPayload{
									MinerAddress: minerAddr,
									BlockIndex:   tmpl.BlockIndex,
									Nonce:        n,
									Timestamp:    blockTimestamp,
									Hash:         solvedHash,
									ReportedHash: solvedHash,
								}
								mm.BroadcastSolvedBlock(httpClient, payload)

								select {
								case triggerUpdate <- struct{}{}:
								default:
								}
							}
							break
						}
					}
					time.Sleep(20 * time.Millisecond)
				}
			}(wID)
		}
	}

	startTime := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastHashes uint64
	for range ticker.C {
		currHashes := atomic.LoadUint64(&totalHashes)
		currSolved := atomic.LoadUint64(&totalSolved)
		hDiff := currHashes - lastHashes
		lastHashes = currHashes
		elapsed := time.Since(startTime).Truncate(time.Second)
		bNano := blockStartUnixNano.Load()
		var blockElapsed time.Duration
		if bNano > 0 {
			blockElapsed = time.Since(time.Unix(0, bNano)).Truncate(time.Second)
		} else {
			blockElapsed = elapsed
		}

		var hRateStr string
		if hDiff >= 1000000 {
			hRateStr = fmt.Sprintf("%.2f MH/s", float64(hDiff)/1000000.0)
		} else if hDiff >= 1000 {
			hRateStr = fmt.Sprintf("%.2f kH/s", float64(hDiff)/1000.0)
		} else {
			hRateStr = fmt.Sprintf("%d H/s", hDiff)
		}

		bIdx := atomic.LoadInt64(&currentBlockIndex)
		fmt.Printf("\r \033[38;2;99;102;241m[VALIDATING]\033[0m Height: #%d | Speed: \033[1;37m%s\033[0m | Hashes: %d | Blocks Won: \033[1;32m%d\033[0m | Block Time: \033[38;2;56;189;248m%s\033[0m | Total Uptime: %s    ",
			bIdx, hRateStr, currHashes, currSolved, blockElapsed, elapsed)
	}
}
