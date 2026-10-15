package emit

import (
	"strings"
	"testing"

	"github.com/virtualbeck/inherit/internal/redact"
	"github.com/virtualbeck/inherit/model"
)

// Redacted values must never become something tofu would push back to the
// account: their attributes go under ignore_changes, whole-value
// placeholders are left out of config, and UNMANAGED_FIELDS.md lists them.
func TestWriteRedactedFieldsUnmanaged(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-0abc",
				ARN: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
				Config: map[string]any{"ami": "ami-1", "instance_type": "t3.micro",
					"user_data_base64": redact.Sentinel}},
			{TFType: "aws_lambda_function", Region: "us-east-1", ID: "fn",
				ARN: "arn:aws:lambda:us-east-1:123456789012:function:fn",
				Config: map[string]any{"function_name": "fn", "role": "arn:aws:iam::123456789012:role/r",
					"handler": "index.handler", "runtime": "nodejs20.x",
					"environment": []any{map[string]any{"variables": map[string]any{
						"LOG_LEVEL": redact.Sentinel, "DB_PASSWORD": redact.Sentinel}}}}},
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1",
				ARN:    "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1",
				Config: map[string]any{"cidr_block": "10.0.0.0/16"}},
		},
	}
	dir := t.TempDir()
	res, err := Write(inv, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Unmanaged != 2 {
		t.Errorf("Unmanaged = %d, want 2", res.Unmanaged)
	}

	compute := read(t, dir, "modules", "compute", "main.tf")
	if strings.Contains(compute, "user_data_base64") && !strings.Contains(compute, "ignore_changes = [user_data_base64]") {
		t.Errorf("user_data_base64 placeholder written into config:\n%s", compute)
	}
	for _, want := range []string{"ignore_changes = [user_data_base64]", "ignore_changes = [environment]"} {
		if !strings.Contains(compute, want) {
			t.Errorf("compute/main.tf missing %q:\n%s", want, compute)
		}
	}
	if strings.Count(compute, "lifecycle") != 2 {
		t.Errorf("want exactly 2 lifecycle blocks (the vpc has nothing redacted):\n%s", compute)
	}

	doc := read(t, dir, "UNMANAGED_FIELDS.md")
	for _, want := range []string{"module.compute.aws_instance.", "`user_data_base64`", "arn:aws:lambda:us-east-1:123456789012:function:fn"} {
		if !strings.Contains(doc, want) {
			t.Errorf("UNMANAGED_FIELDS.md missing %q:\n%s", want, doc)
		}
	}
}
