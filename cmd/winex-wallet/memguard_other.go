//go:build !linux

package main

func enableMemoryProtection() {
	// Platform-specific hook for non-Linux OS (Windows, macOS)
}
