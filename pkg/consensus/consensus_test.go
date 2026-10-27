package consensus

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestAddressValidation(t *testing.T) {
	valid := "WNX5B15097CB2203643C472AB992FA9FB1A"
	if !ValidateAddress(valid) {
		t.Fatalf("Expected valid address %s", valid)
	}
	invalidShort := "WNX12345"
	if ValidateAddress(invalidShort) {
		t.Fatalf("Expected invalid short address %s", invalidShort)
	}
	invalidPrefix := "BTC5B15097CB2203643C472AB992FA9FB1A"
	if ValidateAddress(invalidPrefix) {
		t.Fatalf("Expected invalid prefix address %s", invalidPrefix)
	}
}

func TestDomainSeparatedMessageSignature(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := "Test authentication message"
	sig, err := SignMessageDomainProtected(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed()[1:]) // 64 bytes
	if err := VerifyMessageDomainProtected(pubHex, "", msg, sig); err != nil {
		t.Fatalf("Domain signature verification failed: %v", err)
	}
}

func TestMerkleRoot(t *testing.T) {
	txs := []Transaction{
		{TxID: "00000000000000000000000000000001"},
		{TxID: "00000000000000000000000000000002"},
	}
	root := ComputeMerkleRoot(txs)
	if root == "" || len(root) != 64 {
		t.Fatalf("Invalid merkle root: %s", root)
	}
}

func TestBlockSubsidy(t *testing.T) {
	rew0 := GetBlockRewardSat(0)
	if rew0 != 0 {
		t.Fatalf("Expected 0 reward at height 0, got %d", rew0)
	}
	rew1 := GetBlockRewardSat(1)
	if rew1 != 40*SatoshiPerCoin {
		t.Fatalf("Expected 40 WNX at height 1, got %d", rew1)
	}
	rewHalved := GetBlockRewardSat(125001)
	if rewHalved != 20*SatoshiPerCoin {
		t.Fatalf("Expected 20 WNX at height 125001, got %d", rewHalved)
	}
}

func TestAtomicStateFile(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := tmpDir + "/chain.state.json"
	engine := NewNodeEngine(stateFile, nil)
	if len(engine.state.Blocks) != 1 {
		t.Fatalf("Expected 1 genesis block, got %d", len(engine.state.Blocks))
	}
	if engine.GetBalanceLocked(GenesisVaultAddr) != GenesisSupplySat {
		t.Fatalf("Expected %d satoshis in genesis vault, got %d", GenesisSupplySat, engine.GetBalanceLocked(GenesisVaultAddr))
	}
}
