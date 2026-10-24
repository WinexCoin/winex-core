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

func detectGPUHardware() (bool, string) {
	nvcuda := syscall.NewLazyDLL("nvcuda.dll")
	if nvcuda.Load() == nil {
		return true, "NVIDIA CUDA Hardware Accelerator (nvcuda.dll)"
	}
	opencl := syscall.NewLazyDLL("OpenCL.dll")
	if opencl.Load() == nil {
		return true, "OpenCL Hardware Accelerator (OpenCL.dll)"
	}
	return false, ""
}
