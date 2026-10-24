//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func initTerminalEnv() {
	if os.Getenv("WINEX_IN_TERMINAL") == "1" {
		return
	}
	// Check if process has a controlling interactive terminal (/dev/tty)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		tty.Close()
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		return
	}
	env := append(os.Environ(), "WINEX_IN_TERMINAL=1")

	if runtime.GOOS == "darwin" {
		script := `tell application "Terminal" to do script "` + exePath + `"; activate`
		cmd := exec.Command("osascript", "-e", script)
		cmd.Env = env
		if cmd.Start() == nil {
			os.Exit(0)
		}
		return
	}

	terminals := [][]string{
		{"x-terminal-emulator", "-e", exePath},
		{"konsole", "-e", exePath},
		{"gnome-terminal", "--", exePath},
		{"ptyxis", "--", exePath},
		{"kgx", "-e", exePath},
		{"xfce4-terminal", "-e", exePath},
		{"kitty", exePath},
		{"alacritty", "-e", exePath},
		{"mate-terminal", "-e", exePath},
		{"lxterminal", "-e", exePath},
		{"xterm", "-e", exePath},
	}

	for _, t := range terminals {
		if path, err := exec.LookPath(t[0]); err == nil {
			cmd := exec.Command(path, t[1:]...)
			cmd.Env = env
			if cmd.Start() == nil {
				os.Exit(0)
			}
		}
	}
}

func configureBackgroundProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

func detectGPUHardware() (bool, string) {
	if ok, name := IsNativeGPUAvailable(); ok {
		return true, name
	}
	if runtime.GOOS == "darwin" {
		return true, "Apple Metal / OpenCL Accelerate Framework"
	}
	if _, err := os.Stat("/dev/nvidia0"); err == nil {
		return true, "NVIDIA CUDA Hardware Adapter (/dev/nvidia0)"
	}
	if _, err := os.Stat("/dev/nvidiactl"); err == nil {
		return true, "NVIDIA CUDA Control Adapter (/dev/nvidiactl)"
	}
	cudaLibs := []string{
		"/usr/lib/x86_64-linux-gnu/libcuda.so.1",
		"/usr/lib64/libcuda.so",
		"/usr/local/cuda/lib64/libcudart.so",
		"/usr/lib/x86_64-linux-gnu/libOpenCL.so.1",
		"/usr/lib64/libOpenCL.so",
	}
	for _, lib := range cudaLibs {
		if _, err := os.Stat(lib); err == nil {
			return true, "GPU Compute Acceleration Driver (" + lib + ")"
		}
	}
	if _, err := os.Stat("/dev/dri/renderD128"); err == nil {
		return true, "Direct Rendering GPU Adapter (/dev/dri/renderD128)"
	}
	return false, ""
}
