package emit

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/virtualbeck/inherit/model"
)

func partsString(v any) string {
	t, ok := v.(tmpl)
	if !ok {
		s, _ := v.(string)
		return "LIT:" + s
	}
	var b strings.Builder
	for _, p := range t.parts {
		switch pp := p.(type) {
		case string:
			b.WriteString(pp)
		case hcl.Traversal:
			b.WriteString("<" + pp.RootName() + "." + pp[len(pp)-1].(hcl.TraverseAttr).Name + ">")
		}
	}
	return b.String()
}

func TestParameterize(t *testing.T) {
	r := model.Resource{Account: "123456789012", Region: "us-west-2"}
	var use dataUse

	got := partsString(paramString("arn:aws:iam::123456789012:role/app", r, "us-west-2", &use))
	want := "arn:<data.partition>:iam::<data.account_id>:role/app"
	if got != want {
		t.Errorf("account/partition:\n got %q\nwant %q", got, want)
	}
	if !use.account || !use.part {
		t.Errorf("data-source use not tracked: %+v", use)
	}

	use = dataUse{}
	got = partsString(paramString("arn:aws:sqs:us-west-2:123456789012:q", r, "us-west-2", &use))
	if got != "arn:<data.partition>:sqs:<data.region>:<data.account_id>:q" {
		t.Errorf("region substitution: %q", got)
	}
	if !use.region {
		t.Error("region use not tracked")
	}

	if s := paramString("job-123456789012-output", r, "us-west-2", &use); s != "job-123456789012-output" {
		t.Errorf("non-arn string was rewritten: %v", s)
	}
}

// Aliased resources use their own aws_region instance.
func TestParameterizeAliasedRegion(t *testing.T) {
	r := model.Resource{Account: "123456789012", Region: "us-west-1"}
	var use dataUse

	got := partsString(paramString("arn:aws:kms:us-west-1:123456789012:key/abc", r, "us-east-1", &use))
	if got != "arn:<data.partition>:kms:<data.region>:<data.account_id>:key/abc" {
		t.Errorf("region substitution: %q", got)
	}
	if use.region {
		t.Error("must not mark the default aws_region.current as used")
	}
	if !use.regionAliases["us_west_1"] {
		t.Errorf("must mark the us_west_1-aliased aws_region data source as used: %+v", use.regionAliases)
	}
}

func TestHoist(t *testing.T) {
	cfg := map[string]any{"name": "prod-api", "runtime": "go1.x", "memory_size": float64(256)}
	out, vars := hoist(cfg, "api", "aws_lambda_function", map[string]bool{})
	if len(vars) != 1 || vars[0].name != "api_name" {
		t.Fatalf("vars = %+v", vars)
	}
	rr, ok := out["name"].(ref)
	if !ok || rootName(rr.trav) != "var.api_name" {
		t.Fatalf("name not replaced with var ref: %#v", out["name"])
	}
	if out["runtime"] != "go1.x" {
		t.Errorf("non-hoisted attr changed: %v", out["runtime"])
	}
}
