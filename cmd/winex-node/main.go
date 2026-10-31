package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"winex-consensus"
)

var defaultBootstrapNodes = []string{
	"https://winexcoin.com",
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

func writeJSON(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func main() {
	var port = flag.Int("port", 8081, "Node HTTP listen port")
	var host = flag.String("host", "127.0.0.1", "Node listen address (use 0.0.0.0 for public relay)")
	var daemon = flag.Bool("daemon", false, "Run as headless background P2P daemon (suppresses interactive terminal clear)")
	var bootstrap = flag.String("bootstrap", "https://winexcoin.com", "Comma-separated HTTPS bootstrap seeds")
	flag.Parse()

	if !*daemon {
		ensureInteractiveTerminal()
	}

	var seeds []string
	for _, s := range strings.Split(*bootstrap, ",") {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "https://") {
			seeds = append(seeds, s)
		}
	}
	if len(seeds) == 0 {
		seeds = defaultBootstrapNodes
	}

	dataPath := filepath.Join(getHomeDataDir(), "chain.state.json")
	engine := consensus.NewNodeEngine(dataPath, seeds)

	walletPath := filepath.Join(getHomeDataDir(), "node_wallet.json")
	if nodeWallet, err := consensus.NewNodeWallet(walletPath); err == nil {
		engine.SetWallet(nodeWallet)
		log.Printf("==> Exchange Hot-Wallet subsystem initialized: %s (%d keys loaded)", walletPath, len(nodeWallet.GetAddresses()))
	} else {
		log.Printf("==> Warning: Could not initialize node hot-wallet: %v", err)
	}

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
			"max_supply":             12100000.0,
			"circulating_supply":     st["mining_pool_available"],
			"unmined_pool_remaining": st["pool_remaining"],
			"initial_block_reward":   40.0,
			"current_block_reward":   st["block_reward"],
			"halving_interval":       125000,
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
			blks := engine.GetBlocks(1)
			if len(blks) > 0 {
				rpcOK(blks[0].Index + 1)
			} else {
				rpcOK(1)
			}
		case "getbestblockhash":
			blks := engine.GetBlocks(1)
			if len(blks) > 0 {
				rpcOK(blks[0].Hash)
			} else {
				rpcOK(consensus.GenesisHash)
			}
		case "getblockhash":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing height parameter")
				return
			}
			ref := fmt.Sprintf("%v", req.Params[0])
			blk, _ := engine.GetBlockByHashOrHeight(ref)
			if blk == nil {
				rpcErr(-5, "Block height out of range")
				return
			}
			rpcOK(blk.Hash)
		case "getblock":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing block hash or height parameter")
				return
			}
			ref := fmt.Sprintf("%v", req.Params[0])
			blk, confs := engine.GetBlockByHashOrHeight(ref)
			if blk == nil {
				rpcErr(-5, "Block not found")
				return
			}
			rpcOK(map[string]interface{}{
				"hash":          blk.Hash,
				"confirmations": confs,
				"size":          blk.TxCount*250 + 80,
				"height":        blk.Index,
				"version":       1,
				"merkleroot":    blk.MerkleRoot,
				"tx":            blk.Txs,
				"time":          int64(blk.Timestamp),
				"nonce":         blk.Nonce,
				"difficulty":    blk.Difficulty,
				"previousblockhash": blk.PrevHash,
				"miner":         blk.Miner,
			})
		case "gettransaction", "getrawtransaction":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing tx_id parameter")
				return
			}
			txID := fmt.Sprintf("%v", req.Params[0])
			txData, ok := engine.GetTransactionByID(txID)
			if !ok {
				rpcErr(-5, "No such mempool or blockchain transaction")
				return
			}
			rpcOK(txData)
		case "getbalance":
			if len(req.Params) == 0 {
				// Exchange hot-wallet balance across all managed addresses
				w := engine.GetWallet()
				if w == nil {
					rpcOK(0.0)
					return
				}
				var totalSat int64
				for _, a := range w.GetAddresses() {
					totalSat += engine.GetBalanceLocked(a)
				}
				rpcOK(float64(totalSat) / float64(consensus.SatoshiPerCoin))
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			bal := engine.GetBalance(addr)
			rpcOK(bal["balance"])
		case "getaddressbalance":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing address parameter")
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			rpcOK(engine.GetBalance(addr))
		case "getnewaddress":
			w := engine.GetWallet()
			if w == nil {
				rpcErr(-32603, "Hot-wallet subsystem not active on this node")
				return
			}
			label := ""
			if len(req.Params) > 0 {
				label = fmt.Sprintf("%v", req.Params[0])
			}
			newAddr, err := w.GenerateNewAddress(label)
			if err != nil {
				rpcErr(-32603, fmt.Sprintf("Failed to generate new address: %v", err))
				return
			}
			rpcOK(newAddr)
		case "sendtoaddress":
			if len(req.Params) < 2 {
				rpcErr(-32602, "Usage: sendtoaddress <address> <amount> [fee] [comment]")
				return
			}
			toAddr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			amtFloat := 0.0
			switch v := req.Params[1].(type) {
			case float64:
				amtFloat = v
			case int:
				amtFloat = float64(v)
			case int64:
				amtFloat = float64(v)
			case string:
				_, _ = fmt.Sscanf(v, "%f", &amtFloat)
			}
			if amtFloat <= 0 {
				rpcErr(-3, "Invalid amount for sendtoaddress")
				return
			}
			amountSat := int64(math.Round(amtFloat * float64(consensus.SatoshiPerCoin)))
			feeSat := int64(0)
			if len(req.Params) > 2 {
				if f, ok := req.Params[2].(float64); ok && f > 0 {
					feeSat = int64(math.Round(f * float64(consensus.SatoshiPerCoin)))
				}
			}

			txID, err := engine.SendFromWallet("", toAddr, amountSat, feeSat)
			if err != nil {
				rpcErr(-25, err.Error())
				return
			}
			rpcOK(txID)
		case "sendfrom":
			if len(req.Params) < 3 {
				rpcErr(-32602, "Usage: sendfrom <from_address> <to_address> <amount> [fee]")
				return
			}
			fromAddr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			toAddr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[1]))
			amtFloat := 0.0
			switch v := req.Params[2].(type) {
			case float64:
				amtFloat = v
			case int:
				amtFloat = float64(v)
			case string:
				_, _ = fmt.Sscanf(v, "%f", &amtFloat)
			}
			amountSat := int64(math.Round(amtFloat * float64(consensus.SatoshiPerCoin)))
			feeSat := int64(0)
			if len(req.Params) > 3 {
				if f, ok := req.Params[3].(float64); ok && f > 0 {
					feeSat = int64(math.Round(f * float64(consensus.SatoshiPerCoin)))
				}
			}
			txID, err := engine.SendFromWallet(fromAddr, toAddr, amountSat, feeSat)
			if err != nil {
				rpcErr(-25, err.Error())
				return
			}
			rpcOK(txID)
		case "getreceivedbyaddress":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing address parameter")
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			minConf := int64(1)
			if len(req.Params) > 1 {
				if mc, ok := req.Params[1].(float64); ok {
					minConf = int64(mc)
				}
			}
			coins, _ := engine.GetReceivedByAddress(addr, minConf)
			rpcOK(coins)
		case "listtransactions":
			limit := 50
			addr := ""
			if len(req.Params) > 0 {
				p0 := fmt.Sprintf("%v", req.Params[0])
				if consensus.ValidateAddress(p0) {
					addr = p0
				}
			}
			if len(req.Params) > 1 {
				if l, ok := req.Params[1].(float64); ok && l > 0 {
					limit = int(l)
				}
			}
			if addr != "" {
				rpcOK(engine.GetAddressTransactions(addr, limit))
			} else {
				// Collect for all wallet addresses
				w := engine.GetWallet()
				var allTx []map[string]interface{}
				if w != nil {
					for _, a := range w.GetAddresses() {
						allTx = append(allTx, engine.GetAddressTransactions(a, limit)...)
					}
				}
				rpcOK(allTx)
			}
		case "validateaddress":
			if len(req.Params) == 0 {
				rpcErr(-32602, "Missing address parameter")
				return
			}
			addr := strings.TrimSpace(fmt.Sprintf("%v", req.Params[0]))
			valid := consensus.ValidateAddress(addr)
			isMine := false
			if w := engine.GetWallet(); w != nil {
				isMine = w.HasAddress(addr)
			}
			rpcOK(map[string]interface{}{"isvalid": valid, "address": addr, "ismine": isMine})
		case "getmininginfo":
			rpcOK(engine.GetMiningTemplate())
		case "getnetworkinfo", "getinfo":
			rpcOK(engine.GetStatus())
		case "getpeerinfo":
			st := engine.GetStatus()
			rpcOK(st["peers"])
		default:
			rpcErr(-32601, "Method not found or unsupported")
		}
	}
	mux.HandleFunc("/rpc", handleRPC)
	mux.HandleFunc("/api/rpc", handleRPC)

	mux.HandleFunc("/api/blocks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, engine.GetBlocks(50), 200)
	})

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
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]string{"error": "Invalid payload"}, 400)
			return
		}
		ok, msg := engine.SubmitBlock(req.MinerAddress, req.BlockIndex, req.Nonce, req.Timestamp, req.Hash)
		if ok {
			writeJSON(w, map[string]interface{}{"status": "accepted", "success": true, "message": msg}, 200)
		} else {
			writeJSON(w, map[string]interface{}{"status": "rejected", "success": false, "message": msg}, 400)
		}
	})

	mux.HandleFunc("/api/transaction/send", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		var req struct {
			Sender    string `json:"sender"`
			Recipient string `json:"recipient"`
			AmountSat int64  `json:"amount_sat"`
			FeeSat    int64  `json:"fee_sat"`
			Nonce     int64  `json:"nonce"`
			Timestamp int64  `json:"timestamp"`
			PublicKey string `json:"public_key"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]string{"error": "Invalid payload"}, 400)
			return
		}
		ok, res := engine.AddTransaction(req.Sender, req.Recipient, req.AmountSat, req.FeeSat, req.Nonce, req.Timestamp, req.PublicKey, req.Signature)
		if ok {
			writeJSON(w, map[string]interface{}{"success": true, "tx_id": res}, 200)
		} else {
			writeJSON(w, map[string]interface{}{"success": false, "error": res}, 400)
		}
	})

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Println("\033[38;2;248;250;252m┌──────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[38;2;248;250;252m│ WINEX CORE // HARDENED AUTONOMOUS LAYER-1 VALIDATOR NODE             v4.0.0 │\033[0m")
	fmt.Println("\033[38;2;248;250;252m├──────────────────────────┬───────────────────────────────────────────────────┤\033[0m")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mNODE ROLE\033[0m                \033[38;2;248;250;252m│\033[0m Zero-Trust Consensus Validator & Relay            \033[38;2;248;250;252m│\033[0m\n")
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mLOCAL RPC ENDPOINT\033[0m       \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", "http://"+addr)
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mBOOTSTRAP HTTPS SEED\033[0m     \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", seeds[0])
	fmt.Printf("\033[38;2;248;250;252m│\033[0m \033[38;2;148;163;184mLEDGER STORAGE\033[0m           \033[38;2;248;250;252m│\033[0m %-49s \033[38;2;248;250;252m│\033[0m\n", truncateStr(dataPath, 49))
	fmt.Println("\033[38;2;248;250;252m└──────────────────────────┴───────────────────────────────────────────────────┘\033[0m")

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
