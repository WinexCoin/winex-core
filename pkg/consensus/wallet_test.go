package consensus

import (
	"path/filepath"
	"testing"
)

func TestNodeWallet_GenerateAndSign(t *testing.T) {
	tempDir := t.TempDir()
	walletPath := filepath.Join(tempDir, "node_wallet.json")

	wallet, err := NewNodeWallet(walletPath)
	if err != nil {
		t.Fatalf("Failed to initialize NodeWallet: %v", err)
	}

	addr1, err := wallet.GenerateNewAddress("deposit_user_1")
	if err != nil {
		t.Fatalf("Failed to generate address: %v", err)
	}
	if !ValidateAddress(addr1) {
		t.Fatalf("Generated invalid WNX address: %s", addr1)
	}
	if !wallet.HasAddress(addr1) {
		t.Fatalf("Wallet should recognize owned address %s", addr1)
	}

	tx := &Transaction{
		Sender:    addr1,
		Recipient: "WNX11111111111111111111111111111111",
		AmountSat: 100000000,
		FeeSat:    0,
		Nonce:     1,
		Timestamp: 1740000000,
	}
	canonicalPayload := CanonicalTxPayload(ChainID, tx.Sender, tx.Recipient, tx.AmountSat, tx.FeeSat, tx.Nonce, tx.Timestamp)
	sigHex, pubHex, err := wallet.SignCanonicalTransaction(addr1, canonicalPayload)
	if err != nil {
		t.Fatalf("SignCanonicalTransaction failed: %v", err)
	}
	tx.Signature = sigHex
	tx.PublicKey = pubHex
	tx.TxID = ComputeTxID(ChainID, tx.Sender, tx.Recipient, tx.AmountSat, tx.FeeSat, tx.Nonce, tx.Timestamp)

	if err := VerifyTransactionSignature(tx); err != nil {
		t.Fatalf("VerifyTransactionSignature failed: %v", err)
	}
}
