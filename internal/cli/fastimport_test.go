package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/internal/tf"
)

// requireTF skips unless explicitly asked to run the real thing: these tests
// drive a real tofu/terraform binary and download the hashicorp/local
// provider (no AWS, no credentials, nothing but the local filesystem).
func requireTF(t *testing.T) *tf.Runner {
	t.Helper()
	if os.Getenv("INHERIT_INTEGRATION") == "" {
		t.Skip("set INHERIT_INTEGRATION=1 to run (needs tofu/terraform + the hashicorp/local provider download)")
	}
	dir := t.TempDir()
	r, err := tf.Detect("", dir)
	if err != nil {
		t.Skip(err)
	}
	return r
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rawApply is test scaffolding only (not the code under test): a plain,
// unscoped apply to legitimately seed state via terraform itself, standing
// in for "this resource was already imported with its real, correct
// values". hashicorp/local's local_file has no ImportState implementation,
// so it can't exercise inherit's real import{} block path -- but that path
// is well-established, extensively-documented core Terraform behavior; what
// these tests actually verify is what happens downstream of "a resource is
// in state with real values", which is identical either way.
func rawApply(t *testing.T, r *tf.Runner) {
	t.Helper()
	cmd := exec.Command(r.Bin, "apply", "-auto-approve", "-input=false", "-no-color")
	cmd.Dir = r.Dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seed apply failed: %v\n%s", err, out)
	}
}

// buildFixture lays out a root module calling one child module, mirroring
// inherit's real generated project shape (root main.tf -> module -> resource),
// since WriteImportOverrides and every -target address assume that layout.
func buildFixture(t *testing.T, r *tf.Runner) {
	t.Helper()
	writeFile(t, filepath.Join(r.Dir, "providers.tf"), `terraform {
  required_providers {
    local = { source = "hashicorp/local", version = "~> 2.0" }
  }
}
`)
	writeFile(t, filepath.Join(r.Dir, "main.tf"), `module "network" {
  source = "./modules/network"
}
`)
}

// TestFastImportAppliesOnlyVerifiedNoOpChunks is the happy path, exercised
// through the real applyChunk (plan -> verify -> apply), not a hand-rolled
// replica: a chunk whose resources are already in state with real values,
// but whose generated config has drifted arbitrarily, must apply as a true
// no-op -- the drifted config must never reach the real resource.
func TestFastImportAppliesOnlyVerifiedNoOpChunks(t *testing.T) {
	r := requireTF(t)
	buildFixture(t, r)

	modDir := filepath.Join(r.Dir, "modules", "network")
	writeFile(t, filepath.Join(r.Dir, "realfile", "a.txt"), "REAL CONTENT A\n")
	writeFile(t, filepath.Join(r.Dir, "realfile", "b.txt"), "REAL CONTENT B\n")

	// seed state matching real content (see rawApply)
	writeFile(t, filepath.Join(modDir, "main.tf"), `
resource "local_file" "a" {
  filename = "${path.module}/../../realfile/a.txt"
  content  = "REAL CONTENT A\n"
}
resource "local_file" "b" {
  filename = "${path.module}/../../realfile/b.txt"
  content  = "REAL CONTENT B\n"
}
`)
	if err := r.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	rawApply(t, r)

	// now swap in drastically drifted config -- this is what a hydrator bug,
	// or simply attribute types ignore_changes doesn't help with elsewhere,
	// would look like. It must never reach the real file.
	writeFile(t, filepath.Join(modDir, "main.tf"), `
resource "local_file" "a" {
  filename = "${path.module}/../../realfile/a.txt"
  content  = "WRONG CONTENT FOR A -- must never be written"
}
resource "local_file" "b" {
  filename = "${path.module}/../../realfile/b.txt"
  content  = "WRONG CONTENT FOR B -- must never be written"
}
`)
	imports := []emit.ImportSpec{
		{Addr: "module.network.local_file.a", Cat: "network", TFType: "local_file", Name: "a"},
		{Addr: "module.network.local_file.b", Cat: "network", TFType: "local_file", Name: "b"},
	}
	overridePaths, err := emit.WriteImportOverrides(r.Dir, imports)
	if err != nil {
		t.Fatalf("WriteImportOverrides: %v", err)
	}
	defer emit.RemoveImportOverrides(overridePaths)

	planDir := t.TempDir()
	n, err := applyChunk(context.Background(), r, planDir, 0, imports)
	if err != nil {
		t.Fatalf("applyChunk: %v", err)
	}
	if n != 2 {
		t.Errorf("applyChunk reported %d applied, want 2", n)
	}

	if got := readFile(t, filepath.Join(r.Dir, "realfile", "a.txt")); got != "REAL CONTENT A\n" {
		t.Errorf("a.txt was overwritten despite ignore_changes=all: %q", got)
	}
	if got := readFile(t, filepath.Join(r.Dir, "realfile", "b.txt")); got != "REAL CONTENT B\n" {
		t.Errorf("b.txt was overwritten despite ignore_changes=all: %q", got)
	}
}

// TestFastImportNeverCreatesAnUnimportableResource is the safety-gate case:
// a resource with no way to actually be imported (no import block; local_file
// can't support one anyway) must never be silently created by the fast
// path -- it must fall back to classic import (which also can't import it,
// so it ends up reported as failed, and the run returns an error so the
// command exits non-zero) rather than materialize on disk.
func TestFastImportNeverCreatesAnUnimportableResource(t *testing.T) {
	r := requireTF(t)
	buildFixture(t, r)

	modDir := filepath.Join(r.Dir, "modules", "network")
	writeFile(t, filepath.Join(modDir, "main.tf"), `
resource "local_file" "ghost" {
  filename = "${path.module}/../../realfile/ghost.txt"
  content  = "if this file exists, fast-import created something it should only ever import"
}
`)
	if err := r.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	imports := []emit.ImportSpec{
		{Addr: "module.network.local_file.ghost", ID: "does-not-matter", Cat: "network", TFType: "local_file", Name: "ghost"},
	}
	err := runFastImport(context.Background(), r, r.Dir, imports, 40, 4)
	if err == nil || !strings.Contains(err.Error(), "1 of 1 imports failed") {
		t.Fatalf("runFastImport error = %v, want the failed classic-fallback import reported", err)
	}

	if _, err := os.Stat(filepath.Join(r.Dir, "realfile", "ghost.txt")); !os.IsNotExist(err) {
		t.Fatal("SAFETY VIOLATION: fast-import created a resource that was never actually imported")
	}
	have, err := r.StateList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if have["module.network.local_file.ghost"] {
		t.Error("resource ended up in state despite never being importable")
	}
}

// fastBatches: all-good input takes ceil(n/max) applies; one bad resource is
// isolated by halving, so only a batch of at most minBatch around it goes to
// classic import, and everything else still imports fast, in order.
func TestFastBatchesSplitsAroundFailures(t *testing.T) {
	specs := make([]emit.ImportSpec, 100)
	for i := range specs {
		specs[i] = emit.ImportSpec{Addr: fmt.Sprintf("module.m.t.r%d", i)}
	}
	var calls int
	applyAll := func(b []emit.ImportSpec) (int, error) { calls++; return len(b), nil }
	done, fb, err := fastBatches(context.Background(), specs, 40, 8, applyAll)
	if err != nil || done != 100 || len(fb) != 0 || calls != 3 {
		t.Fatalf("all good: done=%d fallback=%d calls=%d err=%v, want 100/0/3/nil", done, len(fb), calls, err)
	}

	bad := "module.m.t.r57"
	calls = 0
	applyBad := func(b []emit.ImportSpec) (int, error) {
		calls++
		for _, s := range b {
			if s.Addr == bad {
				return 0, errors.New("plan is not import-only")
			}
		}
		return len(b), nil
	}
	done, fb, err = fastBatches(context.Background(), specs, 40, 8, applyBad)
	if err != nil {
		t.Fatal(err)
	}
	if done+len(fb) != 100 || len(fb) == 0 || len(fb) > 8 {
		t.Fatalf("one bad: done=%d fallback=%d, want fallback of 1..8 around it and the rest done", done, len(fb))
	}
	if !slices.ContainsFunc(fb, func(s emit.ImportSpec) bool { return s.Addr == bad }) {
		t.Fatalf("fallback %v doesn't contain the bad resource", fb)
	}
	if calls > 3+2*4 {
		t.Errorf("%d applies to isolate one failure, want at most %d", calls, 3+2*4)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fastBatches(ctx, specs, 40, 8, applyAll); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: err=%v, want context.Canceled", err)
	}
}
