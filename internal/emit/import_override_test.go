package emit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteImportOverrides(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"modules/network", "modules/database"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	imports := []ImportSpec{
		{Addr: "module.network.aws_vpc.main", ID: "vpc-1", Cat: "network", TFType: "aws_vpc", Name: "main"},
		{Addr: "module.network.aws_subnet.a", ID: "subnet-1", Cat: "network", TFType: "aws_subnet", Name: "a"},
		{Addr: "module.database.aws_db_instance.db1", ID: "db1", Cat: "database", TFType: "aws_db_instance", Name: "db1"},
	}

	paths, err := WriteImportOverrides(dir, imports)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("wrote %d files, want 2 (one per category): %v", len(paths), paths)
	}

	net, err := os.ReadFile(filepath.Join(dir, "modules", "network", "import_override.tf"))
	if err != nil {
		t.Fatal(err)
	}
	netStr := string(net)
	if !strings.Contains(netStr, `resource "aws_vpc" "main"`) || !strings.Contains(netStr, `resource "aws_subnet" "a"`) {
		t.Errorf("network override missing a resource stub:\n%s", netStr)
	}
	if strings.Contains(netStr, "aws_db_instance") {
		t.Errorf("network override should not contain a database-module resource:\n%s", netStr)
	}
	if !strings.Contains(netStr, "lifecycle {") || !strings.Contains(netStr, "ignore_changes = all") {
		t.Errorf("override missing lifecycle/ignore_changes:\n%s", netStr)
	}
	// ignore_changes = all must be a bare identifier, not a quoted string --
	// quoting it changes its meaning entirely (a literal attribute named "all").
	if strings.Contains(netStr, `ignore_changes = "all"`) {
		t.Errorf(`ignore_changes must be the bare identifier "all", not a quoted string:\n%s`, netStr)
	}

	db, err := os.ReadFile(filepath.Join(dir, "modules", "database", "import_override.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(db), `resource "aws_db_instance" "db1"`) {
		t.Errorf("database override missing its resource stub:\n%s", db)
	}

	RemoveImportOverrides(paths)
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("RemoveImportOverrides left %s behind", p)
		}
	}
	// removing again (e.g. a defer after a failure that already cleaned up)
	// must not panic or error
	RemoveImportOverrides(paths)
}
