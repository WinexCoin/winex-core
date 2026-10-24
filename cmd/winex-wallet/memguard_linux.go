//go:build linux

package main

import "syscall"

const prSetDumpable = 4 // PR_SET_DUMPABLE in linux/prctl.h

func enableMemoryProtection() {
	// Disable core dumps on crash and disallow unprivileged ptrace / /proc/pid/mem inspection
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, uintptr(prSetDumpable), 0, 0)
}
