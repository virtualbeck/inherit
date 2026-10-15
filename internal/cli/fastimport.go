package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/internal/tf"
)

type tfPlanJSON struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			Actions []string `json:"actions"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// Every change, dependencies included, must be a no-op.
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

// runFastImport: pin, plan, verify no-op, apply that plan.
func runFastImport(ctx context.Context, r *tf.Runner, absOut string, imports []emit.ImportSpec, chunkSize, classicConcurrency int) error {
	if chunkSize <= 0 {
		chunkSize = len(imports)
	}
	if chunkSize == 0 {
		return nil
	}

	pending, skipped := pendingImports(ctx, r, imports)
	if len(pending) == 0 {
		fmt.Fprintf(os.Stderr, "%s fast-import: nothing to do (%d already in state)\n", r.Name(), skipped)
		return nil
	}

	// Cover all imports: -target pulls in dependencies.
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

	fmt.Fprintf(os.Stderr, "%s fast-import (%d resources, %d already in state, batches of up to %d)\n",
		r.Name(), len(pending), skipped, chunkSize)

	seq := 0
	fastDone, fallback, err := fastBatches(ctx, pending, chunkSize, fastImportMinBatch, func(batch []emit.ImportSpec) (int, error) {
		seq++
		return applyChunk(ctx, r, planDir, seq, batch)
	})
	if err != nil {
		return err // interrupted; deferred cleanup removes overrides
	}

	var fallbackErr error
	if len(fallback) > 0 {
		fmt.Fprintf(os.Stderr, "%s import: %d resources need the classic (slower) path\n", r.Name(), len(fallback))
		fallbackErr = runImports(ctx, r, fallback, classicConcurrency)
	}

	fmt.Fprintf(os.Stderr, "  fast-imported %d, already in state %d, fell back to classic import %d\n", fastDone, skipped, len(fallback))
	return fallbackErr
}

// fastBatches halves failing batches down to minBatch.
func fastBatches(ctx context.Context, pending []emit.ImportSpec, maxBatch, minBatch int, apply func([]emit.ImportSpec) (int, error)) (done int, fallback []emit.ImportSpec, err error) {
	queue := slices.Collect(slices.Chunk(pending, max(maxBatch, 1)))
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return done, fallback, ctx.Err()
		}
		batch := queue[0]
		queue = queue[1:]

		n, err := apply(batch)
		switch {
		case err == nil:
			done += n
			fmt.Fprintf(os.Stderr, "  imported %d (%d/%d)\n", n, done, len(pending))
		case ctx.Err() != nil:
			return done, fallback, ctx.Err() // interrupted, not failed
		case len(batch) > minBatch:
			fmt.Fprintf(os.Stderr, "  ! batch of %d: %v -- splitting\n", len(batch), err)
			mid := len(batch) / 2
			queue = append([][]emit.ImportSpec{batch[:mid], batch[mid:]}, queue...)
		default:
			fmt.Fprintf(os.Stderr, "  ! batch of %d: %v -- falling back to classic import\n", len(batch), err)
			fallback = append(fallback, batch...)
		}
	}
	return done, fallback, nil
}

// applyChunk plans, verifies and applies; nothing on failure.
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

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
