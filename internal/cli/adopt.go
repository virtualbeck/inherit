package cli

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/spf13/cobra"
	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/internal/par"
	"github.com/virtualbeck/inherit/internal/tf"
	"github.com/zclconf/go-cty/cty"
)

const (
	// Imports queue on the state lock anyway.
	importConcurrency = 4

	// Fewer tofu runs; still fits Windows' argv limit.
	fastImportChunk = 200
	// Failing batches halve to this, then go classic.
	fastImportMinBatch = 8
)

func planCmd() *cobra.Command {
	var tfBin string
	cmd := &cobra.Command{
		Use:   "plan [dir]",
		Short: "Run tofu init + validate + plan against a generated project (no state changes)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adopt(cmd.Context(), dirArg(args), tfBin, "")
		},
	}
	cmd.Flags().StringVar(&tfBin, "tf-bin", "", "path to tofu/terraform (default: auto-detect, prefer tofu)")
	return cmd
}

func importCmd() *cobra.Command {
	var (
		tfBin string
		fast  bool
	)
	cmd := &cobra.Command{
		Use:   "import [dir]",
		Short: "init + validate, import every resource into local state, then plan",
		Long: "Imports every resource in imports.tf into local state, then plans.\n\n" +
			"Default: one classic `import` per resource -- only ever calls the provider's\n" +
			"Read, never Create/Update/Delete.\n\n" +
			"--fast: batches imports through native import blocks + apply, far faster on\n" +
			"large accounts. Every batch is pinned to `ignore_changes = all`, planned to a\n" +
			"file, and applied only if that plan is verified to contain nothing but no-op\n" +
			"imports; a batch that fails either check is split in half and retried, and\n" +
			"only small batches that still fail fall back to classic import.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := "import"
			if fast {
				mode = "fast-import"
			}
			return adopt(cmd.Context(), dirArg(args), tfBin, mode)
		},
	}
	cmd.Flags().StringVar(&tfBin, "tf-bin", "", "path to tofu/terraform (default: auto-detect, prefer tofu)")
	cmd.Flags().BoolVar(&fast, "fast", false, "batched, plan-verified import (much faster at scale)")
	return cmd
}

// adopt runs init, validate, optional import, then plan.
func adopt(ctx context.Context, dir, tfBin, mode string) error {
	absDir, _ := filepath.Abs(dir)

	var imports []emit.ImportSpec
	if mode != "" {
		var err error
		if imports, err = readImports(absDir); err != nil {
			return err
		}
	}

	runner, err := tf.Detect(tfBin, absDir)
	if err != nil {
		return err
	}
	name := runner.Name()

	fmt.Fprintf(os.Stderr, "%s init\n", name)
	if err := runner.Init(ctx); err != nil {
		return fmt.Errorf("%s init: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "%s validate\n", name)
	if err := runner.Validate(ctx); err != nil {
		return fmt.Errorf("%s validate: %w", name, err)
	}

	// Plan still runs; import failures fail the command.
	var importErr error
	switch mode {
	case "fast-import":
		importErr = runFastImport(ctx, runner, absDir, imports, fastImportChunk, importConcurrency)
	case "import":
		importErr = runImports(ctx, runner, imports, importConcurrency)
	}
	if ctx.Err() != nil {
		return importErr
	}

	fmt.Fprintf(os.Stderr, "%s plan\n", name)
	if err := runner.Plan(ctx); err != nil {
		return errors.Join(importErr, fmt.Errorf("%s plan: %w (see above)", name, err))
	}
	if importErr != nil {
		return importErr
	}
	fmt.Fprintf(os.Stderr, "\ndone. project: %s\n", absDir)
	return nil
}

// pendingImports skips addresses already in state.
func pendingImports(ctx context.Context, r *tf.Runner, specs []emit.ImportSpec) (pending []emit.ImportSpec, skipped int) {
	have, _ := r.StateList(ctx)
	for _, s := range specs {
		if have[s.Addr] {
			skipped++
			continue
		}
		pending = append(pending, s)
	}
	return pending, skipped
}

// readImports parses imports.tf as HCL; bad blocks error.
func readImports(dir string) ([]emit.ImportSpec, error) {
	path := filepath.Join(dir, "imports.tf")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading imports.tf (run `inherit scan` first): %w", err)
	}
	f, diags := hclsyntax.ParseConfig(b, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	var specs []emit.ImportSpec
	for _, blk := range f.Body.(*hclsyntax.Body).Blocks {
		if blk.Type != "import" {
			continue
		}
		spec, err := importSpec(blk)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", blk.DefRange(), err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// importSpec reads to = module.<cat>.<type>.<name>[key].
func importSpec(blk *hclsyntax.Block) (emit.ImportSpec, error) {
	to, ok := blk.Body.Attributes["to"]
	if !ok {
		return emit.ImportSpec{}, fmt.Errorf("import block has no `to`")
	}
	idAttr, ok := blk.Body.Attributes["id"]
	if !ok {
		return emit.ImportSpec{}, fmt.Errorf("import block has no `id`")
	}
	idVal, diags := idAttr.Expr.Value(nil)
	if diags.HasErrors() || idVal.Type() != cty.String || idVal.IsNull() {
		return emit.ImportSpec{}, fmt.Errorf("import `id` must be a literal string")
	}
	trav, diags := hcl.AbsTraversalForExpr(to.Expr)
	if diags.HasErrors() || len(trav) < 4 || len(trav) > 5 || trav.RootName() != "module" {
		return emit.ImportSpec{}, fmt.Errorf("import `to` must be module.<category>.<type>.<name>[key]")
	}
	var parts [3]string
	for i := range parts {
		a, ok := trav[i+1].(hcl.TraverseAttr)
		if !ok {
			return emit.ImportSpec{}, fmt.Errorf("import `to` must be module.<category>.<type>.<name>[key]")
		}
		parts[i] = a.Name
	}
	cat, typ, name := parts[0], parts[1], parts[2]
	key := ""
	if len(trav) == 5 {
		idx, ok := trav[4].(hcl.TraverseIndex)
		if !ok || idx.Key.Type() != cty.String || idx.Key.IsNull() {
			return emit.ImportSpec{}, fmt.Errorf("import `to` index must be a string key")
		}
		key = idx.Key.AsString()
	}
	return emit.ImportSpec{
		Addr:   emit.ResourceAddr(cat, typ, name, key),
		ID:     idVal.AsString(),
		Cat:    cat,
		TFType: typ,
		Name:   name,
	}, nil
}

// Transient tofu import failures: throttling, lock contention.
var retryable = regexp.MustCompile(`(?i)throttl|rate exceeded|too many requests|slow ?down|request ?limit ?exceeded|error acquiring the state lock|resource temporarily unavailable`)

func importOne(ctx context.Context, r *tf.Runner, addr, id string) (string, error) {
	const maxAttempts = 8
	const base = 300 * time.Millisecond
	const capWait = 8 * time.Second
	var out string
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		out, err = r.Import(ctx, addr, id)
		if err == nil || attempt == maxAttempts || !retryable.MatchString(out) {
			return out, err
		}
		wait := min(base*time.Duration(1<<uint(attempt-1)), capWait)
		wait = wait/2 + mathrand.N(wait/2+1)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}
	return out, err
}

// runImports runs classic import; errors if any failed.
func runImports(ctx context.Context, r *tf.Runner, specs []emit.ImportSpec, concurrency int) error {
	concurrency = max(concurrency, 1)
	pending, skipped := pendingImports(ctx, r, specs)
	fmt.Fprintf(os.Stderr, "%s import (%d resources, state-only, up to %d at a time)\n", r.Name(), len(pending), concurrency)

	var (
		mu     sync.Mutex
		done   int
		failed int
		n      int
	)
	par.Each(pending, concurrency, func(s emit.ImportSpec) {
		if ctx.Err() != nil {
			return // interrupted
		}
		out, err := importOne(ctx, r, s.Addr, s.ID)
		mu.Lock()
		defer mu.Unlock()
		n++
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  ! %s: %v\n%s\n", s.Addr, err, strings.TrimSpace(out))
		} else {
			done++
		}
		if n%25 == 0 || n == len(pending) {
			fmt.Fprintf(os.Stderr, "  %d/%d done\n", n, len(pending))
		}
	})
	fmt.Fprintf(os.Stderr, "  imported %d, already in state %d, failed %d\n", done, skipped, failed)
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case failed > 0:
		return fmt.Errorf("%d of %d imports failed (see above); re-run to retry just those", failed, len(pending))
	}
	return nil
}
