package cli

import (
	"context"
	"os"
	"path/filepath"
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
