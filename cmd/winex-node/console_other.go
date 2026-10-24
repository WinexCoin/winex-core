//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
)

func initTerminalEnv() {
	ensureInteractiveTerminal()
}

func ensureInteractiveTerminal() {
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
