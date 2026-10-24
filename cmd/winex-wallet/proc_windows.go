//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	enableVirtualTerminalProcessing = 0x0004
	cpUTF8                          = 65001
)

func initTerminalEnv() {
	enableMemoryProtection()
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	setConsoleCP := kernel32.NewProc("SetConsoleCP")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	_, _, _ = setConsoleOutputCP.Call(uintptr(cpUTF8))
	_, _, _ = setConsoleCP.Call(uintptr(cpUTF8))

	hOut := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getConsoleMode.Call(uintptr(hOut), uintptr(unsafe.Pointer(&mode)))
	if r != 0 {
		_, _, _ = setConsoleMode.Call(uintptr(hOut), uintptr(mode|enableVirtualTerminalProcessing))
	}
}

func configureBackgroundProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}

func ensureInteractiveTerminal() {
	initTerminalEnv()
}

func configureNoConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
}

func openURLNative(url string) error {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")
	verb, _ := syscall.UTF16PtrFromString("open")
	target, _ := syscall.UTF16PtrFromString(url)
	r, _, _ := shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
	if r <= 32 {
		return syscall.GetLastError()
	}
	return nil
}
