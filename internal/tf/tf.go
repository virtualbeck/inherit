// Package tf drives a local tofu/terraform binary: init, validate, plan, and
// import. Classic per-resource Import never runs `apply` -- it only ever
// calls a provider's Read. PlanTargeted/ShowJSON/ApplyPlanFile exist for the
// --fast-import path, which does run `apply`, but only ever against a plan
// file the caller has already verified (via ShowJSON) contains nothing but
// no-op imports -- see internal/cli's runFastImport for the safety gate.
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

// interruptGrace is how long a cancelled tofu/terraform gets to finish
// cleanly (release the state lock, persist state) after being interrupted,
// before it's killed.
const interruptGrace = 30 * time.Second

// output selects what run captures.
type output int

const (
	stream   output = iota // stdout+stderr to our stderr, live
	combined               // stdout+stderr captured together (human-readable logs)
	stdout                 // stdout captured alone (machine-readable); stderr goes into the error
)

// Runner is a resolved tofu/terraform binary bound to a working directory.
type Runner struct {
	Bin string
	Dir string
}

// Detect finds a binary. explicit wins; otherwise tofu is preferred, then
// terraform.
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

// Name is "tofu" or "terraform" for messages.
func (r *Runner) Name() string {
	return strings.TrimSuffix(filepath.Base(r.Bin), ".exe")
}

// run executes the binary in r.Dir. Cancelling ctx interrupts it rather than
// killing it outright (a SIGKILL mid-import can leave the state lock held or
// state half-written), and only kills it if it hasn't exited within
// interruptGrace. See proc_*.go for the platform specifics.
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

// Init runs `init -input=false`.
func (r *Runner) Init(ctx context.Context) error {
	_, err := r.run(ctx, stream, "init", "-input=false", "-no-color")
	return err
}

// Validate runs `validate`.
func (r *Runner) Validate(ctx context.Context) error {
	_, err := r.run(ctx, stream, "validate", "-no-color")
	return err
}

// Plan runs `plan -input=false -lock=false` (read-only, no state lock needed).
func (r *Runner) Plan(ctx context.Context) error {
	_, err := r.run(ctx, stream, "plan", "-input=false", "-lock=false", "-no-color")
	return err
}

// StateList returns the addresses already present in local state.
func (r *Runner) StateList(ctx context.Context) (map[string]bool, error) {
	out, err := r.run(ctx, stdout, "state", "list", "-no-color")
	if err != nil {
		// empty / missing state is not an error for our purposes
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

// Import runs `import <addr> <id>` and returns its combined output. This
// only writes local state -- classic `import` calls nothing but the
// provider's Read, never Create/Update/Delete. State locking is left on
// (unlike Plan, which never writes state): callers may run many of these
// concurrently against the same local state file, and the lock is what
// keeps those writes from corrupting it. The local backend's lock is a
// non-blocking flock by default (0s timeout, fails immediately on
// contention) -- with real concurrency that's the common case, not an edge
// case, so -lock-timeout tells `import` to poll and wait for the lock
// itself instead of failing fast; that's far cheaper than a caller retrying
// the whole subprocess (repeating the slow network Read) just to fail on
// the lock again. Output is always captured (never streamed to os.Stderr
// directly) so concurrent callers don't interleave garbled output from
// multiple subprocesses on the same terminal.
func (r *Runner) Import(ctx context.Context, addr, id string) (string, error) {
	return r.run(ctx, combined, "import", "-input=false", "-no-color", "-lock-timeout=120s", addr, id)
}

// PlanTargeted runs a read-only plan restricted to targets (module-qualified
// addresses) and saves it to planFile for a later ShowJSON/ApplyPlanFile.
// -lock=false: this only reads and writes a local plan artifact, never
// terraform.tfstate itself, the same reasoning as Plan. A nonzero error here
// (e.g. one target's import { } block couldn't resolve because the real
// resource is gone) means no usable plan file was produced -- callers must
// not proceed to ShowJSON/ApplyPlanFile in that case.
func (r *Runner) PlanTargeted(ctx context.Context, planFile string, targets []string) (string, error) {
	args := []string{"plan", "-input=false", "-lock=false", "-no-color", "-out=" + planFile}
	for _, t := range targets {
		args = append(args, "-target="+t)
	}
	return r.run(ctx, combined, args...)
}

// ShowJSON returns `show -json planFile`: the plan's structured JSON
// representation, most importantly each resource's planned change.actions.
func (r *Runner) ShowJSON(ctx context.Context, planFile string) ([]byte, error) {
	out, err := r.run(ctx, stdout, "show", "-json", "-no-color", planFile)
	return []byte(out), err
}

// ApplyPlanFile applies a plan file saved by PlanTargeted, verbatim: the
// exact scope and actions already computed, nothing re-planned. No -target
// here (or anywhere else) -- the plan file already encodes the target scope,
// and re-targeting an apply-from-plan isn't accepted by tofu/terraform.
func (r *Runner) ApplyPlanFile(ctx context.Context, planFile string) (string, error) {
	return r.run(ctx, combined, "apply", "-input=false", "-no-color", "-auto-approve", "-lock-timeout=120s", planFile)
}
