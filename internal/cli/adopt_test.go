package cli

import (
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
