package nodecore

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"winex-consensus"
)

type NodeEngine = consensus.NodeEngine

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

func Run(host string, port int) {
	dataPath := filepath.Join(getHomeDataDir(), "chain.state.json")
	engine := consensus.NewNodeEngine(dataPath, []string{"https://winexcoin.com"})

	TryAutoUPnP(port)
	StartLANAutoDiscovery(engine, port)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = consensus.WriteJSON(w, engine.GetStatus(), 200)
	})
	mux.HandleFunc("/api/blocks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = consensus.WriteJSON(w, engine.GetBlocks(50), 200)
	})
	mux.HandleFunc("/api/mining/template", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = consensus.WriteJSON(w, engine.GetMiningTemplate(), 200)
	})

	server := &http.Server{
		Addr:        fmt.Sprintf("%s:%d", host, port),
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}
	_ = server.ListenAndServe()
}
