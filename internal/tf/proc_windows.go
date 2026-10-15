//go:build windows

package tf

import (
	"os"
	"os/exec"
)

func isolate(*exec.Cmd) {}

// Windows has no interrupt signal; kill instead.
func interrupt(p *os.Process) error { return p.Kill() }
