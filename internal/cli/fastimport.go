package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/internal/tf"
)

// tfPlanJSON is the slice of `tofu show -json <planfile>` this package reads:
// enough to verify a plan's safety, nothing more.
type tfPlanJSON struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			Actions []string `json:"actions"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// verifyImportOnlyPlan reports whether every resource change in a plan is
// exactly a no-op (the only shape ApplyPlanFile is ever allowed to see for
// --fast-import). `-target` pulls in anything a targeted resource directly
// references as a dependency even if it wasn't explicitly listed, so this
// checks every entry the plan actually contains, not just the requested
// target list -- a pulled-in dependency that isn't a safe no-op must block
// the apply exactly the same as an explicitly targeted one would.
//
// An empty ResourceChanges list is safe trivially: there is nothing for
// ApplyPlanFile to do.
func verifyImportOnlyPlan(planJSON []byte) (bool, string) {
	var p tfPlanJSON
	if err := json.Unmarshal(planJSON, &p); err != nil {
		return false, fmt.Sprintf("could not parse plan JSON: %v", err)
	}
	for _, rc := range p.ResourceChanges {
		if len(rc.Change.Actions) != 1 || rc.Change.Actions[0] != "no-op" {
			return false, fmt.Sprintf("%s would be %v, not a plain no-op import", rc.Address, rc.Change.Actions)
		}
	}
	return true, ""
}

// runFastImport bulk-imports via native `import` blocks + `apply`, batched
// in chunks, instead of one `terraform import` subprocess per resource (see
// runImports). This is dramatically cheaper at scale -- one process per
// chunk instead of one per resource, each with the full local-state
// read/parse/write overhead -- but apply is a strictly more powerful (and
// more dangerous) operation than classic import's Read-only Import, so
// every chunk goes through a hard, structural gate before anything is ever
// applied:
//
//  1. Every resource gets `lifecycle { ignore_changes = all }` for the
//     duration of this run, via a transient override file (removed
//     afterward regardless of outcome) -- so no live attribute can ever be
//     pushed to match config, no matter what the generated config says.
//  2. Each chunk is planned (read-only, saved to a plan file) and NOT
//     applied yet.
//  3. The saved plan's JSON is inspected: every single resource change in
//     it -- including anything pulled in only as a dependency -- must be
//     exactly a no-op import. Anything else (a create, an update a defeated
//     ignore_changes somehow missed, a replace) aborts that chunk before
//     apply ever runs.
//  4. Only a chunk that passes step 3 gets applied, and only the exact
//     saved plan from step 2 -- nothing is re-planned at apply time.
//
// A chunk that fails at any step (plan errors -- e.g. a resource's import
// target no longer exists -- or fails verification) falls back to the slow
// but unconditionally-safe classic per-resource import (runImports) for
// just that chunk's resources, not the whole run.
func runFastImport(ctx context.Context, r *tf.Runner, absOut string, imports []emit.ImportSpec, chunkSize, classicConcurrency int) error {
	if chunkSize <= 0 {
		chunkSize = len(imports)
	}
	if chunkSize == 0 {
		return nil
	}

	have, _ := r.StateList(ctx)
	var pending []emit.ImportSpec
	skipped := 0
	for _, s := range imports {
		if have[s.Addr] {
			skipped++
			continue
		}
		pending = append(pending, s)
	}
	if len(pending) == 0 {
		fmt.Fprintf(os.Stderr, "%s fast-import: nothing to do (%d already in state)\n", r.Name(), skipped)
		return nil
	}

	// Overrides cover every import-covered resource, not just this run's
	// pending set: a chunk's -target can pull in an already-imported
	// resource as a dependency, and it needs the same ignore_changes = all
	// protection as everything else being applied in that same plan.
	overridePaths, err := emit.WriteImportOverrides(absOut, imports)
	if err != nil {
		return fmt.Errorf("writing import overrides: %w", err)
	}
	defer emit.RemoveImportOverrides(overridePaths)

	planDir, err := os.MkdirTemp(absOut, ".fastimport-")
	if err != nil {
		return fmt.Errorf("creating fast-import scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(planDir) }()

	fmt.Fprintf(os.Stderr, "%s fast-import (%d resources, %d already in state, chunks of %d)\n",
		r.Name(), len(pending), skipped, chunkSize)

	var fallback []emit.ImportSpec
	fastDone := 0

	for i := 0; i < len(pending); i += chunkSize {
		end := min(i+chunkSize, len(pending))
		chunk := pending[i:end]
		label := fmt.Sprintf("%d-%d/%d", i+1, end, len(pending))

		n, err := applyChunk(ctx, r, planDir, i/chunkSize, chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! chunk %s: %v -- falling back to classic import for this chunk\n", label, err)
			fallback = append(fallback, chunk...)
			continue
		}
		fastDone += n
		fmt.Fprintf(os.Stderr, "  chunk %s: imported %d\n", label, n)
	}

	if len(fallback) > 0 {
		fmt.Fprintf(os.Stderr, "%s import: %d resources need the classic (slower) path\n", r.Name(), len(fallback))
		if err := runImports(ctx, r, fallback, classicConcurrency); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "  fast-imported %d, already in state %d, fell back to classic import %d\n", fastDone, skipped, len(fallback))
	return nil
}

// applyChunk runs the plan -> verify -> apply sequence for one chunk. On any
// failure it returns an error describing what went wrong and applies
// nothing; the caller falls the whole chunk back to classic import.
func applyChunk(ctx context.Context, r *tf.Runner, planDir string, idx int, chunk []emit.ImportSpec) (int, error) {
	targets := make([]string, len(chunk))
	for i, s := range chunk {
		targets[i] = s.Addr
	}

	planFile := filepath.Join(planDir, fmt.Sprintf("chunk-%d.tfplan", idx))
	planOut, err := r.PlanTargeted(ctx, planFile, targets)
	if err != nil {
		return 0, fmt.Errorf("plan failed: %s", firstLine(planOut))
	}

	planJSON, err := r.ShowJSON(ctx, planFile)
	if err != nil {
		return 0, fmt.Errorf("could not inspect plan: %w", err)
	}
	if safe, reason := verifyImportOnlyPlan(planJSON); !safe {
		return 0, fmt.Errorf("plan is not import-only: %s", reason)
	}

	if _, err := r.ApplyPlanFile(ctx, planFile); err != nil {
		return 0, fmt.Errorf("apply failed despite a verified import-only plan (unexpected): %w", err)
	}
	return len(chunk), nil
}

// firstLine trims an error/output blob down to its most informative line for
// a one-line progress log; the full text is redundant here since a failed
// chunk's resources get retried individually via classic import, which
// prints its own per-resource error output.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
