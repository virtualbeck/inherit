package nameconv

import "testing"

func TestSnake(t *testing.T) {
	cases := map[string]string{
		"VpcId":                "vpc_id",
		"CidrBlock":            "cidr_block",
		"ARN":                  "arn",
		"KmsKeyId":             "kms_key_id",
		"DBInstanceIdentifier": "db_instance_identifier",
		"IPv6CidrBlock":        "ipv6_cidr_block",
		"MapPublicIpOnLaunch":  "map_public_ip_on_launch",
		"Name":                 "name",
		"MaxSessionDuration":   "max_session_duration",
		// found via aws_ecs_capacity_provider.managed_instances_provider.
		// instance_requirements: single-trailing-capital acronyms
		// (VCpu/MiB/GiB) the generic rule mangles the same way IPv4/IPv6
		// once did, just not caught until a field name actually used them.
		"VCpuCount":                 "vcpu_count",
		"MemoryMiB":                 "memory_mib",
		"AcceleratorTotalMemoryMiB": "accelerator_total_memory_mib",
		"MemoryGiBPerVCpu":          "memory_gib_per_vcpu",
	}
	for in, want := range cases {
		if got := Snake(in); got != want {
			t.Errorf("Snake(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSnakeKeys(t *testing.T) {
	in := map[string]any{
		"VpcId":  "vpc-1",
		"Tags":   []any{map[string]any{"Key": "Name", "Value": "x"}},
		"Nested": map[string]any{"CidrBlock": "10.0.0.0/16"},
	}
	got := SnakeKeys(in).(map[string]any)
	if got["vpc_id"] != "vpc-1" {
		t.Fatalf("vpc_id missing: %v", got)
	}
	if got["nested"].(map[string]any)["cidr_block"] != "10.0.0.0/16" {
		t.Fatalf("nested not converted: %v", got)
	}
	if got["tags"].([]any)[0].(map[string]any)["key"] != "Name" {
		t.Fatalf("slice element not converted: %v", got)
	}
}
