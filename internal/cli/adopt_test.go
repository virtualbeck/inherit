package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func TestRetryableRegex(t *testing.T) {
	yes := []string{
		"Error: error importing: ThrottlingException: Rate exceeded",
		"operation error IAM: ListRoles, https response error StatusCode: 400, RequestLimitExceeded",
		"Too Many Requests",
		"SlowDown: please reduce your request rate",
		"Error: Error acquiring the state lock\n\nError message: resource temporarily unavailable",
	}
	no := []string{
		"Cannot import non-existent remote object",
		"could not parse import ID as ARN: arn: invalid prefix",
		"the provider detected that no object exists with the given id",
	}
	for _, s := range yes {
		if !retryable.MatchString(s) {
			t.Errorf("expected retryable to match: %q", s)
		}
	}
	for _, s := range no {
		if retryable.MatchString(s) {
			t.Errorf("expected retryable NOT to match: %q", s)
		}
	}
}

func TestReadImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/imports.tf", `# header
import {
  to = module.network.aws_vpc.main
  id = "vpc-0abc"
}

import {
  to = module.compute.aws_subnet.private["us-east-1a"]
  id = "subnet-1"
}
`)
	specs, err := readImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2: %+v", len(specs), specs)
	}
	if specs[0].Addr != "module.network.aws_vpc.main" || specs[0].ID != "vpc-0abc" {
		t.Errorf("spec 0 wrong: %+v", specs[0])
	}
	if specs[1].Addr != `module.compute.aws_subnet.private["us-east-1a"]` || specs[1].ID != "subnet-1" {
		t.Errorf("spec 1 wrong: %+v", specs[1])
	}
}

func TestReadImportsEscapingAndShape(t *testing.T) {
	dir := t.TempDir()
	f := hclwrite.NewEmptyFile()
	b := f.Body().AppendNewBlock("import", nil).Body()
	b.SetAttributeTraversal("to", hcl.Traversal{
		hcl.TraverseRoot{Name: "module"}, hcl.TraverseAttr{Name: "security"},
		hcl.TraverseAttr{Name: "aws_iam_policy"}, hcl.TraverseAttr{Name: "p"},
		hcl.TraverseIndex{Key: cty.StringVal(`we"ird\key`)},
	})
	b.SetAttributeValue("id", cty.StringVal(`arn:${x}:"q"\z`))
	writeFile(t, dir+"/imports.tf", string(f.Bytes()))

	specs, err := readImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(specs))
	}
	if got, want := specs[0].ID, `arn:${x}:"q"\z`; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got, want := specs[0].Addr, `module.security.aws_iam_policy.p["we\"ird\\key"]`; got != want {
		t.Errorf("Addr = %s, want %s", got, want)
	}

	writeFile(t, dir+"/imports.tf", "import {\n  to = aws_vpc.main\n  id = \"vpc-1\"\n}\n")
	if _, err := readImports(dir); err == nil {
		t.Error("an import outside module.<category> should be an error, not skipped")
	}
}

// A hard-killed fast import's overrides hide all drift.
func TestAdoptRemovesLeftoverOverrides(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "modules", "network", "import_override.tf")
	scratch := filepath.Join(dir, ".fastimport-123")
	for _, d := range []string{filepath.Dir(override), scratch} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, override, "resource \"aws_vpc\" \"main\" {\n  lifecycle {\n    ignore_changes = all\n  }\n}\n")
	writeFile(t, filepath.Join(dir, "modules", "network", "main.tf"), "# keep\n")

	// Cleanup runs before tofu is needed.
	err := adopt(context.Background(), dir, "no-such-tofu-binary", "")
	if err == nil || !strings.Contains(err.Error(), "no tofu or terraform") {
		t.Fatalf("want the missing-binary error, got %v", err)
	}
	for _, p := range []string{override, scratch} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should be gone (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "modules", "network", "main.tf")); err != nil {
		t.Errorf("main.tf must be kept: %v", err)
	}
}
