package main

import (
	"strings"
	"testing"
)

func TestIsSafeMinerEndpoint(t *testing.T) {
	// 1. Loopback nodes on port 8081 are explicitly allowed
	if !IsSafeMinerEndpoint("http://127.0.0.1:8081") {
		t.Fatalf("Expected http://127.0.0.1:8081 to be safe")
	}
	if !IsSafeMinerEndpoint("http://localhost:8081") {
		t.Fatalf("Expected http://localhost:8081 to be safe")
	}

	// 2. Remote HTTPS endpoints are allowed
	if !IsSafeMinerEndpoint("https://winexcoin.com") {
		t.Fatalf("Expected https://winexcoin.com to be safe")
	}

	// 3. SSRF: Remote HTTP (unencrypted) MUST be rejected
	if IsSafeMinerEndpoint("http://remote-attacker-node.com:8081") {
		t.Fatalf("Expected remote plain HTTP to be rejected (SSRF / downgrade guard)")
	}

	// 4. SSRF: Private RFC1918 IPs MUST be rejected
	privateTargets := []string{
		"https://10.0.0.1:8081",
		"https://192.168.1.1:8081",
		"https://172.16.0.1:8081",
		"http://10.0.0.1:8081",
		"https://169.254.169.254", // Cloud AWS/GCP metadata service
		"https://100.64.0.1",      // Carrier Grade NAT
	}
	for _, target := range privateTargets {
		if IsSafeMinerEndpoint(target) {
			t.Fatalf("Expected private/metadata IP %s to be blocked by SSRF filter!", target)
		}
	}

	// 5. Malformed URLs
	if IsSafeMinerEndpoint("not-a-url") {
		t.Fatalf("Expected malformed URL to be rejected")
	}
}

func TestValidateMiningJobInputs(t *testing.T) {
	validPrefix := "1:00003789c9e082b2310f3212f4af4aa6daded8d3e8861285ea6c74fd37cfd1a4:merkle:WNX5B15097CB2203643C472AB992FA9FB1A:1740000000.0000:"
	validSalt := strings.Repeat("a", 64)
	validTarget := strings.Repeat("0", 64)

	// Valid inputs
	if !ValidateMiningJobInputs(validPrefix, validSalt, validTarget) {
		t.Fatalf("Expected valid inputs to pass validation")
	}

	// Oversized prefix (> 340 bytes) to prevent kernel buffer overrun
	hugePrefix := strings.Repeat("x", 400)
	if ValidateMiningJobInputs(hugePrefix, validSalt, validTarget) {
		t.Fatalf("Expected oversized prefix to be rejected")
	}

	// Malformed salt length
	if ValidateMiningJobInputs(validPrefix, "short_salt", validTarget) {
		t.Fatalf("Expected short salt to be rejected")
	}

	// Malformed target length
	if ValidateMiningJobInputs(validPrefix, validSalt, "short_target") {
		t.Fatalf("Expected short target to be rejected")
	}
}
