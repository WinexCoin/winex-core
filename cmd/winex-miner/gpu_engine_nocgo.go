//go:build !cgo || !linux

package main

func IsNativeGPUAvailable() (bool, string) {
	return false, ""
}

func RunGPUBatch(prefix, saltHex, targetHex string, startNonce uint64, batchSize uint32) (bool, uint64, string) {
	return false, 0, ""
}
