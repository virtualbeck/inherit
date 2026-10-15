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
	"strings"
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
	b := r.Bin
	if i := strings.LastIndexByte(b, '/'); i >= 0 {
		b = b[i+1:]
	}
	return b
}

func (r *Runner) run(ctx context.Context, capture bool, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, r.Bin, args...)
	cmd.Dir = r.Dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	var out bytes.Buffer
	if capture {
		cmd.Stdout = &out
		cmd.Stderr = &out
	} else {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	return out.String(), err
}

// Init runs `init -input=false`.
func (r *Runner) Init(ctx context.Context) error {
	_, err := r.run(ctx, false, "init", "-input=false", "-no-color")
	return err
}

// Validate runs `validate`.
func (r *Runner) Validate(ctx context.Context) error {
	_, err := r.run(ctx, false, "validate", "-no-color")
	return err
}

// Plan runs `plan -input=false -lock=false` (read-only, no state lock needed).
func (r *Runner) Plan(ctx context.Context) error {
	_, err := r.run(ctx, false, "plan", "-input=false", "-lock=false", "-no-color")
	return err
}

// StateList returns the addresses already present in local state.
func (r *Runner) StateList(ctx context.Context) (map[string]bool, error) {
	out, err := r.run(ctx, true, "state", "list", "-no-color")
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
	return r.run(ctx, true, "import", "-input=false", "-no-color", "-lock-timeout=120s", addr, id)
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
	return r.run(ctx, true, args...)
}

// ShowJSON returns `show -json planFile`: the plan's structured JSON
// representation, most importantly each resource's planned change.actions.
func (r *Runner) ShowJSON(ctx context.Context, planFile string) ([]byte, error) {
	out, err := r.run(ctx, true, "show", "-json", "-no-color", planFile)
	return []byte(out), err
}

// ApplyPlanFile applies a plan file saved by PlanTargeted, verbatim: the
// exact scope and actions already computed, nothing re-planned. No -target
// here (or anywhere else) -- the plan file already encodes the target scope,
// and re-targeting an apply-from-plan isn't accepted by tofu/terraform.
func (r *Runner) ApplyPlanFile(ctx context.Context, planFile string) (string, error) {
	return r.run(ctx, true, "apply", "-input=false", "-no-color", "-auto-approve", "-lock-timeout=120s", planFile)
}
