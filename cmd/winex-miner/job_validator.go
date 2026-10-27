package main

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ValidateMiningJobInputs ensures prefix, salt, and target buffers conform to
// maximum buffer bounds (340 bytes) and valid 64-character hexadecimal encoding
// to prevent buffer overflow panics on CPU and GPU kernels.
func ValidateMiningJobInputs(prefix, saltHex, targetHex string) bool {
	// Prefix format: index:prev_hash:merkle:miner:timestamp:
	// Maximum buffer in CPU/OpenCL kernel is 384 bytes, reserving 32+ bytes for int64/uint64 nonce string
	if len(prefix) == 0 || len(prefix) > 340 {
		return false
	}
	// Salt must be exact 64-character hex
	if len(saltHex) != 64 || !isHex(saltHex) {
		return false
	}
	// Target must be exact 64-character hex
	if len(targetHex) != 64 || !isHex(targetHex) {
		return false
	}
	return true
}
