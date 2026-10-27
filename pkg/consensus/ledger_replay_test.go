package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type failStorageWriter struct{}

func (f *failStorageWriter) WriteAtomic(path string, data []byte) error {
	return errors.New("simulated disk write I/O error")
}

func SignMessageCanonical(privKey *btcec.PrivateKey, message string) (string, error) {
	h := sha256.Sum256([]byte(message))
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

func TestMempoolConfirmedBalanceSeparation(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := tmpDir + "/mempool_test.json"
	engine := NewNodeEngine(stateFile, nil)

	// Generate sender key corresponding to genesis vault or new address
	// For testing, GenesisVaultAddr has GenesisSupplySat
	// We check spendable vs confirmed
	initialConfirmed := engine.GetBalanceLocked(GenesisVaultAddr)
	if initialConfirmed != GenesisSupplySat {
		t.Fatalf("Expected %d confirmed, got %d", GenesisSupplySat, initialConfirmed)
	}

	spendable := engine.GetSpendableBalanceLocked(GenesisVaultAddr)
	if spendable != initialConfirmed {
		t.Fatalf("Expected initial spendable %d == confirmed %d", spendable, initialConfirmed)
	}

	// Manually inject a pending mempool tx for 100 WNX from GenesisVaultAddr
	pendingTx := Transaction{
		TxID:      "test_tx_1",
		Sender:    GenesisVaultAddr,
		Recipient: "WNX11111111111111111111111111111111",
		AmountSat: 100 * SatoshiPerCoin,
		FeeSat:    1 * SatoshiPerCoin,
		Nonce:     1,
		Timestamp: time.Now().Unix(),
	}
	engine.state.Mempool = append(engine.state.Mempool, pendingTx)

	// Confirmed balance MUST NOT have changed
	if engine.GetBalanceLocked(GenesisVaultAddr) != GenesisSupplySat {
		t.Fatalf("Confirmed balance must NOT mutate on mempool entry: expected %d, got %d",
			GenesisSupplySat, engine.GetBalanceLocked(GenesisVaultAddr))
	}

	// Recipient MUST NOT have confirmed balance from unconfirmed pending tx
	if engine.GetBalanceLocked("WNX11111111111111111111111111111111") != 0 {
		t.Fatalf("Unconfirmed recipient balance must be 0, got %d",
			engine.GetBalanceLocked("WNX11111111111111111111111111111111"))
	}

	// Spendable balance for sender MUST be reduced by pending reservation (101 WNX)
	expectedSpendable := GenesisSupplySat - (101 * SatoshiPerCoin)
	if engine.GetSpendableBalanceLocked(GenesisVaultAddr) != expectedSpendable {
		t.Fatalf("Expected spendable %d, got %d", expectedSpendable, engine.GetSpendableBalanceLocked(GenesisVaultAddr))
	}
}

func TestReplayAndVerifyLedgerTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := tmpDir + "/replay_test.json"
	engine := NewNodeEngine(stateFile, nil)

	// Mine a valid Block #1
	prevHash := GenesisHash
	merkle := ComputeMerkleRoot([]Transaction{})
	minerAddr := "WNXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ts := 1740000100.0

	// Find valid nonce with "000000" prefix
	var validNonce int64 = -1
	var validHash string
	for n := int64(0); n < 5000000; n++ {
		h := ComputePowHash(1, prevHash, merkle, minerAddr, ts, n)
		if h[:6] == "000000" {
			validNonce = n
			validHash = h
			break
		}
	}
	if validNonce == -1 {
		t.Skip("Could not find PoW solution quickly in test environment")
	}

	ok, msg := engine.SubmitBlock(minerAddr, 1, validNonce, ts, validHash)
	if !ok {
		t.Fatalf("Failed to commit valid Block #1: %s", msg)
	}

	// 1. TAMPER TEST: Modify miner reward to create unearned coins
	tamperedBlocks := make([]Block, len(engine.state.Blocks))
	copy(tamperedBlocks, engine.state.Blocks)
	tamperedBlocks[1].RewardSat += 100 * SatoshiPerCoin // illegal extra subsidy
	_, _, _, err := engine.ReplayAndVerifyLedger(tamperedBlocks)
	if err == nil {
		t.Fatalf("Expected ReplayAndVerifyLedger to reject tampered block subsidy!")
	}

	// 2. TAMPER TEST: Modify transaction list without updating merkle root
	tamperedBlocks2 := make([]Block, len(engine.state.Blocks))
	copy(tamperedBlocks2, engine.state.Blocks)
	tamperedBlocks2[1].Txs = append(tamperedBlocks2[1].Txs, Transaction{
		TxID: "fake_injected_tx", AmountSat: 1000,
	})
	_, _, _, err = engine.ReplayAndVerifyLedger(tamperedBlocks2)
	if err == nil {
		t.Fatalf("Expected ReplayAndVerifyLedger to reject block with merkle mismatch!")
	}
}

func TestPersistenceFailureRollbackWithMockStorage(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := tmpDir + "/rollback_mock.json"
	engine := NewNodeEngine(stateFile, nil)

	// Inject failing storage writer
	engine.SetStorageWriter(&failStorageWriter{})

	origSpendable := engine.GetSpendableBalanceLocked(GenesisVaultAddr)
	origMempoolLen := len(engine.state.Mempool)

	// Attempting to add an invalid or valid transaction where saveToDiskAtomic fails
	// Must not leave orphaned state
	ok, _ := engine.AddTransaction(GenesisVaultAddr, "WNX22222222222222222222222222222222", 1000, 0, 1, time.Now().Unix(), "dummy", "dummy")
	if ok {
		t.Fatalf("Expected transaction addition to fail")
	}

	// Mempool and spendable must be untouched
	if len(engine.state.Mempool) != origMempoolLen {
		t.Fatalf("Mempool changed despite failure: %d != %d", len(engine.state.Mempool), origMempoolLen)
	}
	if engine.GetSpendableBalanceLocked(GenesisVaultAddr) != origSpendable {
		t.Fatalf("Spendable balance changed despite failure")
	}
}
