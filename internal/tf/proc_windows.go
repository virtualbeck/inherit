//go:build windows

package tf

import (
	"os"
	"os/exec"
	"syscall"
)

var generateConsoleCtrlEvent = syscall.NewLazyDLL("kernel32.dll").NewProc("GenerateConsoleCtrlEvent")

// Own group: Ctrl-Break reaches tofu alone.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// Go reads Ctrl-Break as interrupt; kill if unsendable.
func interrupt(p *os.Process) error {
	const ctrlBreakEvent = 1
	if ok, _, _ := generateConsoleCtrlEvent.Call(ctrlBreakEvent, uintptr(p.Pid)); ok != 0 {
		return nil
	}
	return p.Kill()
}
