package prune

import (
	"testing"

	"github.com/virtualbeck/inherit-core/model"
)

func names(inv model.Inventory) map[string]bool {
	m := map[string]bool{}
	for _, r := range inv.Resources {
		m[r.TFType+"/"+r.ID] = true
	}
	return m
}

func TestNoiseDropsUnusedDefaultsAndRegions(t *testing.T) {
	inv := model.Inventory{
		Regions: []string{"us-east-1", "eu-west-1", "ap-south-1"},
		Resources: []model.Resource{
			// us-east-1: real work + its own (unused) default VPC
			{TFType: "aws_s3_bucket", Region: "us-east-1", ID: "b1"},
			{TFType: "aws_default_vpc", Region: "us-east-1", ID: "vpc-0e1e1e1e"},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-0e1e1e1e",
				Config: map[string]any{"name": "default", "vpc_id": "vpc-0e1e1e1e"}},
			{TFType: "aws_vpc_security_group_egress_rule", Region: "us-east-1", ID: "sgr-0e1e1e1e",
				Config: map[string]any{"security_group_id": "sg-0e1e1e1e"}},
			{TFType: "aws_ebs_encryption_by_default", Region: "us-east-1", ID: "us-east-1",
				Config: map[string]any{"enabled": false}},
			// eu-west-1: nothing but defaults + singletons -> whole region goes
			{TFType: "aws_default_vpc", Region: "eu-west-1", ID: "vpc-0eece0ec"},
			{TFType: "aws_backup_region_settings", Region: "eu-west-1", ID: "eu-west-1"},
			// ap-south-1: a used default VPC (an instance lives in it) -> kept
			{TFType: "aws_default_vpc", Region: "ap-south-1", ID: "vpc-0a0a0a0a"},
			{TFType: "aws_instance", Region: "ap-south-1", ID: "i-0a0a0a0a",
				Config: map[string]any{"vpc_security_group_ids": []any{"sg-04a04a04"}, "subnet_id": "subnet-0b0b0b0b", "network": map[string]any{"vpc": "vpc-0a0a0a0a"}}},
		},
	}
	rep := Noise(&inv, Options{})

	got := names(inv)
	for _, want := range []string{"aws_s3_bucket/b1", "aws_default_vpc/vpc-0a0a0a0a", "aws_instance/i-0a0a0a0a"} {
		if !got[want] {
			t.Errorf("expected %s kept", want)
		}
	}
	for _, gone := range []string{
		"aws_default_vpc/vpc-0e1e1e1e", "aws_security_group/sg-0e1e1e1e",
		"aws_vpc_security_group_egress_rule/sgr-0e1e1e1e",
		"aws_ebs_encryption_by_default/us-east-1",
		"aws_default_vpc/vpc-0eece0ec", "aws_backup_region_settings/eu-west-1",
	} {
		if got[gone] {
			t.Errorf("expected %s pruned", gone)
		}
	}
	if len(inv.Regions) != 2 || inv.Regions[0] != "us-east-1" || inv.Regions[1] != "ap-south-1" {
		t.Errorf("regions = %v, want [us-east-1 ap-south-1]", inv.Regions)
	}
	if len(rep.Regions) != 1 || rep.Regions[0] != "eu-west-1" {
		t.Errorf("dropped regions = %v", rep.Regions)
	}
	if rep.Defaults == 0 || rep.Singletons != 2 {
		t.Errorf("report = %+v", rep)
	}
}

func TestNoiseKeepsDeliberateSecurityPosture(t *testing.T) {
	inv := model.Inventory{
		Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_iam_role", Region: "", ID: "r"},
			{TFType: "aws_ebs_encryption_by_default", Region: "us-east-1", ID: "us-east-1",
				Config: map[string]any{"enabled": true}},
			{TFType: "aws_api_gateway_account", Region: "us-east-1", ID: "us-east-1",
				Config: map[string]any{"cloudwatch_role_arn": "arn:aws:iam::1:role/x"}},
		},
	}
	Noise(&inv, Options{})
	if len(inv.Resources) != 3 {
		t.Errorf("kept %d, want 3 (enabled encryption + configured apigw account stay)", len(inv.Resources))
	}
}

func TestNoiseIncludeDefaultsIsNoop(t *testing.T) {
	inv := model.Inventory{
		Regions:   []string{"eu-west-1"},
		Resources: []model.Resource{{TFType: "aws_default_vpc", Region: "eu-west-1", ID: "vpc-0eece0ec"}},
	}
	rep := Noise(&inv, Options{IncludeDefaults: true})
	if !rep.Empty() || len(inv.Resources) != 1 || len(inv.Regions) != 1 {
		t.Errorf("include-defaults should be a no-op: rep=%+v res=%d", rep, len(inv.Resources))
	}
}

func TestNoiseKeepAllRegions(t *testing.T) {
	inv := model.Inventory{
		Regions: []string{"us-east-1", "eu-west-1"},
		Resources: []model.Resource{
			{TFType: "aws_s3_bucket", Region: "us-east-1", ID: "b1"},
			{TFType: "aws_default_vpc", Region: "eu-west-1", ID: "vpc-0eece0ec"},
		},
	}
	rep := Noise(&inv, Options{KeepAllRegions: true})
	if len(rep.Regions) != 0 {
		t.Errorf("KeepAllRegions must not drop regions, dropped %v", rep.Regions)
	}
	if len(inv.Regions) != 2 {
		t.Errorf("regions trimmed despite KeepAllRegions: %v", inv.Regions)
	}
	if rep.Defaults != 1 {
		t.Errorf("still expected the unused default VPC pruned")
	}
}
