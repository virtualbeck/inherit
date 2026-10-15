// Package tf drives tofu; applies only verified plans.
package tf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Time to release the lock and persist state.
const interruptGrace = 30 * time.Second

type output int

const (
	stream   output = iota // live, to our stderr
	combined               // captured together
	stdout                 // stdout only; stderr goes into the error
)

type Runner struct {
	Bin string
	Dir string
}

// Detect prefers explicit, then tofu, then terraform.
func Detect(explicit, dir string) (*Runner, error) {
	cands := []string{explicit}
	if explicit == "" {
		cands = []string{"tofu", "terraform"}
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return &Runner{Bin: p, Dir: dir}, nil
		}
	}
	return nil, fmt.Errorf("no tofu or terraform on PATH (set --tf-bin)")
}

func (r *Runner) Name() string {
	return strings.TrimSuffix(filepath.Base(r.Bin), ".exe")
}

// Cancel interrupts, then kills after interruptGrace.
func (r *Runner) run(ctx context.Context, mode output, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, r.Bin, args...)
	cmd.Dir = r.Dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	isolate(cmd)
	cmd.Cancel = func() error { return interrupt(cmd.Process) }
	cmd.WaitDelay = interruptGrace

	var out, errOut bytes.Buffer
	switch mode {
	case stream:
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	case combined:
		cmd.Stdout, cmd.Stderr = &out, &out
	case stdout:
		cmd.Stdout, cmd.Stderr = &out, &errOut
	}
	err := cmd.Run()
	if err != nil && errOut.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), err
}

func (r *Runner) Init(ctx context.Context) error {
	_, err := r.run(ctx, stream, "init", "-input=false", "-no-color")
	return err
}

func (r *Runner) Validate(ctx context.Context) error {
	_, err := r.run(ctx, stream, "validate", "-no-color")
	return err
}

// Plan never writes state; no lock needed.
func (r *Runner) Plan(ctx context.Context) error {
	_, err := r.run(ctx, stream, "plan", "-input=false", "-lock=false", "-no-color")
	return err
}

func (r *Runner) StateList(ctx context.Context) (map[string]bool, error) {
	out, err := r.run(ctx, stdout, "state", "list", "-no-color")
	if err != nil {
		// no state yet
		return map[string]bool{}, nil
	}
	set := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			set[s] = true
		}
	}
	return set, nil
}

// Import writes local state, waiting for the lock.
func (r *Runner) Import(ctx context.Context, addr, id string) (string, error) {
	return r.run(ctx, combined, "import", "-input=false", "-no-color", "-lock-timeout=120s", addr, id)
}

// PlanTargeted saves a read-only targeted plan to planFile.
func (r *Runner) PlanTargeted(ctx context.Context, planFile string, targets []string) (string, error) {
	args := []string{"plan", "-input=false", "-lock=false", "-no-color", "-out=" + planFile}
	for _, t := range targets {
		args = append(args, "-target="+t)
	}
	return r.run(ctx, combined, args...)
}

func (r *Runner) ShowJSON(ctx context.Context, planFile string) ([]byte, error) {
	out, err := r.run(ctx, stdout, "show", "-json", "-no-color", planFile)
	return []byte(out), err
}

// ApplyPlanFile applies a saved plan exactly; never re-plans.
func (r *Runner) ApplyPlanFile(ctx context.Context, planFile string) (string, error) {
	return r.run(ctx, combined, "apply", "-input=false", "-no-color", "-auto-approve", "-lock-timeout=120s", planFile)
}
