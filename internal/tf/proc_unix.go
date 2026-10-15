//go:build !windows

package tf

import (
	"os"
	"os/exec"
	"syscall"
)

// isolate puts the child in its own process group, so a terminal Ctrl-C
// reaches only inherit, which forwards exactly one interrupt via
// interrupt. tofu/terraform treat a second interrupt as "exit immediately",
// which is what the graceful path exists to avoid.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func interrupt(p *os.Process) error { return p.Signal(os.Interrupt) }
