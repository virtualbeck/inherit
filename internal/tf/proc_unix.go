//go:build !windows

package tf

import (
	"os"
	"os/exec"
	"syscall"
)

// Own group: tofu must see exactly one interrupt.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func interrupt(p *os.Process) error { return p.Signal(os.Interrupt) }
