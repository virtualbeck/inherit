package cli

import (
	"context"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/internal/tf"
)

const (
	importConcurrency = 32
	fastImportChunk   = 40
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
			"imports; a batch that fails either check falls back to classic import.",
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

// adopt runs init + validate, the optional import mode ("", "import", or
// "fast-import"), then plan.
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
		return fmt.Errorf("%s validate failed", name)
	}

	switch mode {
	case "fast-import":
		if err := runFastImport(ctx, runner, absDir, imports, fastImportChunk, importConcurrency); err != nil {
			return err
		}
	case "import":
		if err := runImports(ctx, runner, imports, importConcurrency); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "%s plan\n", name)
	if err := runner.Plan(ctx); err != nil {
		return fmt.Errorf("%s plan reported problems (see above)", name)
	}
	fmt.Fprintf(os.Stderr, "\ndone. project: %s\n", absDir)
	return nil
}

// importBlockRe matches one import {} block as emit writes it:
//
//	import {
//	  to = module.<cat>.<type>.<name>["<key>"]
//	  id = "<id>"
//	}
var importBlockRe = regexp.MustCompile(`(?s)import\s*\{\s*to\s*=\s*module\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)(?:\["([^"]*)"\])?\s*id\s*=\s*"([^"]*)"\s*\}`)

// readImports pulls the import{} blocks emit wrote into imports.tf back out
// as ImportSpecs, so import can run without a fresh generate.
func readImports(dir string) ([]emit.ImportSpec, error) {
	b, err := os.ReadFile(filepath.Join(dir, "imports.tf"))
	if err != nil {
		return nil, fmt.Errorf("reading imports.tf (run `inherit scan` first): %w", err)
	}
	var specs []emit.ImportSpec
	for _, m := range importBlockRe.FindAllStringSubmatch(string(b), -1) {
		cat, typ, nm, key, id := m[1], m[2], m[3], m[4], m[5]
		addr := "module." + cat + "." + typ + "." + nm
		if key != "" {
			addr += `["` + key + `"]`
		}
		specs = append(specs, emit.ImportSpec{Addr: addr, ID: id, Cat: cat, TFType: typ, Name: nm})
	}
	return specs, nil
}

// retryable matches known-transient failure signatures in `tofu import`
// output: AWS/provider rate-limiting, and local state-lock contention.
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

func runImports(ctx context.Context, r *tf.Runner, specs []emit.ImportSpec, concurrency int) error {
	if concurrency <= 0 {
		concurrency = 1
	}
	have, _ := r.StateList(ctx)

	var pending []emit.ImportSpec
	skipped := 0
	for _, s := range specs {
		if have[s.Addr] {
			skipped++
			continue
		}
		pending = append(pending, s)
	}
	fmt.Fprintf(os.Stderr, "%s import (%d resources, state-only, up to %d at a time)\n", r.Name(), len(pending), concurrency)

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		sem    = make(chan struct{}, concurrency)
		done   int
		failed int
		n      int
	)
	for _, s := range pending {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
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
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "  imported %d, already in state %d, failed %d\n", done, skipped, failed)
	return nil
}
