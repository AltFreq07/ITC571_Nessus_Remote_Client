//go:build windows

package main

import "syscall"

func isAdminWindows() bool {
	mod := syscall.MustLoadDLL("shell32.dll")
	proc := mod.MustFindProc("IsUserAnAdmin")
	ret, _, _ := proc.Call()
	return ret != 0
}
