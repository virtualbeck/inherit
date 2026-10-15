//go:build windows

package tf

import (
	"os"
	"os/exec"
)

// isolate is a no-op: Windows can't deliver an interrupt to another process.
func isolate(*exec.Cmd) {}

// interrupt kills outright; there is no interrupt signal to send on Windows.
func interrupt(p *os.Process) error { return p.Kill() }
