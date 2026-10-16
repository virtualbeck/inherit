package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/virtualbeck/inherit/internal/tf"
)

// Fixture in, project out; tofu validate when integrating.
func TestGenerateFixture(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "typical-account.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, inventoryFile), string(b))

	inv, err := readInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := generate(inv, dir, genFlags{forEach: true}); err != nil {
		t.Fatal(err)
	}

	for _, f := range []string{"versions.tf", "providers.tf", "main.tf", "imports.tf", "backend.tf", "README.md", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if gi := readFile(t, filepath.Join(dir, ".gitignore")); !strings.Contains(gi, secretsFile) || !strings.Contains(gi, "*.tfstate") {
		t.Errorf(".gitignore must cover the secrets file and state:\n%s", gi)
	}
	specs, err := readImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) == 0 {
		t.Fatal("imports.tf has no import blocks")
	}

	if os.Getenv("INHERIT_INTEGRATION") == "" {
		return
	}
	r, err := tf.Detect("", dir)
	if err != nil {
		t.Skip(err)
	}
	ctx := context.Background()
	if err := r.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := r.Validate(ctx); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// A re-run must not keep files it no longer writes.
func TestGenerateRemovesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "typical-account.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, inventoryFile), string(b))
	full, err := readInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := generate(full, dir, genFlags{forEach: true}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"modules/network/outputs.tf", "modules/security/main.tf"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("fixture no longer produces %s; pick another: %v", f, err)
		}
	}
	// User files and directories must survive.
	writeFile(t, filepath.Join(dir, "modules", "network", "NOTES.md"), "mine")
	if err := os.MkdirAll(filepath.Join(dir, "modules", "custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "modules", "custom", "main.tf"), "# mine\n")
	writeFile(t, filepath.Join(dir, "modules", "network", "import_override.tf"), "# leftover\n")

	// Drop the security group (network's only output) and all of IAM.
	reduced := full
	reduced.Resources = nil
	for _, r := range full.Resources {
		switch {
		case r.Service == "iam", r.TFType == "aws_security_group", r.TFType == "aws_vpc_security_group_ingress_rule":
		default:
			reduced.Resources = append(reduced.Resources, r)
		}
	}
	if err := generate(reduced, dir, genFlags{forEach: true}); err != nil {
		t.Fatal(err)
	}

	gone := []string{"modules/network/outputs.tf", "modules/network/import_override.tf", "modules/security"}
	for _, f := range gone {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s should have been removed (err=%v)", f, err)
		}
	}
	kept := []string{"modules/network/NOTES.md", "modules/network/main.tf", "modules/custom/main.tf"}
	for _, f := range kept {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s should have been kept: %v", f, err)
		}
	}

	if os.Getenv("INHERIT_INTEGRATION") == "" {
		return
	}
	r, err := tf.Detect("", dir)
	if err != nil {
		t.Skip(err)
	}
	ctx := context.Background()
	if err := r.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := r.Validate(ctx); err != nil {
		t.Fatalf("validate after regenerating: %v", err)
	}
}

// Rewriting must not keep a looser mode.
func TestWriteJSONResetsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	path := filepath.Join(t.TempDir(), secretsFile)
	writeFile(t, path, "{}")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(path, []string{"x"}, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}
