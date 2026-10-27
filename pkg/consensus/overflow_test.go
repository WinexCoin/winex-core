package consensus

import (
	"encoding/hex"
	"math"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestIntegerOverflowProtection(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := tmpDir + "/overflow_test.json"
	engine := NewNodeEngine(stateFile, nil)

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed()[1:])
	recipAddr := "WNX11111111111111111111111111111111"

	now := time.Now().Unix()

	// 1. MaxInt64 amount overflow check
	ok, msg := engine.AddTransaction(GenesisVaultAddr, recipAddr, math.MaxInt64, 100, 1, now, pubHex, "dummy_sig")
	if ok {
		t.Fatalf("Expected MaxInt64 overflow transaction to be rejected, got success")
	}
	if msg == "" {
		t.Fatalf("Expected descriptive error message on overflow")
	}

	// 2. Amount + Fee overflow check (amount = MaxInt64 - 5, fee = 10)
	ok, _ = engine.AddTransaction(GenesisVaultAddr, recipAddr, math.MaxInt64-5, 10, 1, now, pubHex, "dummy_sig")
	if ok {
		t.Fatalf("Expected amount+fee overflow to be rejected")
	}

	// 3. Negative amount check
	ok, _ = engine.AddTransaction(GenesisVaultAddr, recipAddr, -100, 10, 1, now, pubHex, "dummy_sig")
	if ok {
		t.Fatalf("Expected negative amount to be rejected")
	}

	// 4. Negative fee check
	ok, _ = engine.AddTransaction(GenesisVaultAddr, recipAddr, 1000, -5, 1, now, pubHex, "dummy_sig")
	if ok {
		t.Fatalf("Expected negative fee to be rejected")
	}

	// 5. Amount exceeding MaxSupplySat check
	ok, _ = engine.AddTransaction(GenesisVaultAddr, recipAddr, MaxSupplySat+1, 0, 1, now, pubHex, "dummy_sig")
	if ok {
		t.Fatalf("Expected amount > MaxSupply to be rejected")
	}

	// Verify ledger state integrity remained intact (Genesis balance did not increase or leak)
	bal := engine.GetBalanceLocked(GenesisVaultAddr)
	if bal != GenesisSupplySat {
		t.Fatalf("Expected genesis vault balance to remain %d, got %d", GenesisSupplySat, bal)
	}
	if len(engine.state.Mempool) != 0 {
		t.Fatalf("Expected empty mempool after rejected overflows, got %d txs", len(engine.state.Mempool))
	}
}

func TestRollbackOnDiskFailure(t *testing.T) {
	// Create read-only path to simulate atomic save failure
	tmpDir := t.TempDir()
	readOnlyDir := tmpDir + "/readonly"
	if err := os.Mkdir(readOnlyDir, 0500); err != nil {
		t.Fatal(err)
	}
	stateFile := readOnlyDir + "/chain.state.json"
	engine := NewNodeEngine(stateFile, nil)

	// Attempting a state transition that fails disk write must not corrupt in-memory state
	origBal := engine.GetBalanceLocked(GenesisVaultAddr)
	ok, _ := engine.AddTransaction(GenesisVaultAddr, "WNX22222222222222222222222222222222", 1000, 0, 1, time.Now().Unix(), "dummy", "dummy")
	if ok {
		t.Fatalf("Expected failure due to readonly filesystem")
	}
	if engine.GetBalanceLocked(GenesisVaultAddr) != origBal {
		t.Fatalf("Expected in-memory rollback on persistence failure")
	}
}
