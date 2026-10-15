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
	// quoted "all" would mean an attribute named all
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
	// removing twice is harmless
	RemoveImportOverrides(paths)
}

// Groups share one block; failed writes leave nothing.
func TestWriteImportOverridesDedupAndAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "modules", "network"), 0o755); err != nil {
		t.Fatal(err)
	}
	imports := []ImportSpec{
		{Addr: `module.network.aws_subnet.private["a"]`, Cat: "network", TFType: "aws_subnet", Name: "private"},
		{Addr: `module.network.aws_subnet.private["b"]`, Cat: "network", TFType: "aws_subnet", Name: "private"},
	}
	if _, err := WriteImportOverrides(dir, imports); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "modules", "network", "import_override.tf"))
	if n := strings.Count(string(got), `resource "aws_subnet" "private"`); n != 1 {
		t.Errorf("want 1 override block for the for_each group, got %d:\n%s", n, got)
	}

	// zzz has no module directory, so it fails
	imports = append(imports, ImportSpec{Addr: "module.zzz.aws_vpc.main", Cat: "zzz", TFType: "aws_vpc", Name: "main"})
	paths, err := WriteImportOverrides(dir, imports)
	if err == nil {
		t.Fatal("expected an error writing into a missing module directory")
	}
	if len(paths) != 0 {
		t.Errorf("paths on error = %v, want none", paths)
	}
	if _, err := os.Stat(filepath.Join(dir, "modules", "network", "import_override.tf")); !os.IsNotExist(err) {
		t.Errorf("network override left behind after a failed write (stat err: %v)", err)
	}
}
