package emit

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/virtualbeck/inherit/model"
)

func TestScrubExternalIDs(t *testing.T) {
	cases := []struct {
		in   string
		want bool // want it treated as an external id
	}{
		{"vpc-0abc1234", true},
		{"sg-0d3ebe25da01402e", true}, // 17-hex long form
		{"ami-08b1c2d3", true},        // non-_id attr name in practice
		{"i-0123456789abcdef0", true},
		{"arn:aws:iam::aws:policy/ReadOnly", true},
		{"10.0.0.0/16", false},     // CIDR, not an id
		{"my-subnet-group", false}, // human name with hyphens
		{"family:7", false},        // ecs task def "family:revision"
		{"sg-short", false},        // too short / not hex
	}
	for _, c := range cases {
		if got := looksLikeExternalID(c.in); got != c.want {
			t.Errorf("looksLikeExternalID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A raw AWS id in a nested block, under a non-_id attribute name, and inside
// a list must all be hoisted out of the module body into variables/main.tf.
func TestScrubReachesEverywhere(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-1", Tags: map[string]string{"Name": "app"},
				Config: map[string]any{
					"ami":           "ami-0fedcba9", // non-_id attr
					"instance_type": "t3.micro",
					"network_interface": []any{map[string]any{ // nested block
						"network_interface_id": "eni-0a1b2c3d",
						"device_index":         float64(0),
					}},
					"secondary_private_ips":  []any{},                             // untouched
					"vpc_security_group_ids": []any{"sg-01234567", "sg-89abcdef"}, // list of ids
				}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	main := read(t, dir, "modules", "compute", "main.tf")
	for _, raw := range []string{"ami-0fedcba9", "eni-0a1b2c3d", "sg-01234567", "sg-89abcdef"} {
		if strings.Contains(main, raw) {
			t.Errorf("raw id %q still in the module body:\n%s", raw, main)
		}
	}
	if !strings.Contains(main, "var.ami") {
		t.Errorf("ami not hoisted to a variable:\n%s", main)
	}
	// the literals resurface only in the root main.tf (as module arguments)
	// and variables.tf defaults are absent (these are required inputs).
	root := read(t, dir, "main.tf")
	for _, raw := range []string{"ami-0fedcba9", "sg-01234567"} {
		if !strings.Contains(root, raw) {
			t.Errorf("root main.tf should supply %q as a module argument:\n%s", raw, root)
		}
	}
	// everything still parses
	if _, diag := hclparse.NewParser().ParseHCL([]byte(main), "main.tf"); diag.HasErrors() {
		t.Errorf("generated main.tf does not parse: %s", diag)
	}
}
