package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// managed_instances_provider maps onto the schema almost entirely by SDK
// field name -- the one thing that breaks it is nameconv.Snake mishandling
// VCpu/MiB/GiB acronyms (VCpuCount -> v_cpu_count instead of vcpu_count).
// This exercises the real nested path end to end, not just the isolated
// Snake() cases.
func TestManagedInstancesProviderShape(t *testing.T) {
	sch, err := schemaFor("aws_ecs_capacity_provider")
	if err != nil {
		t.Fatal(err)
	}
	nb, ok := sch.NestedBlock("managed_instances_provider")
	if !ok {
		t.Fatal("managed_instances_provider block missing from schema")
	}

	mip := &ecstypes.ManagedInstancesProvider{
		InfrastructureRoleArn: aws.String("arn:aws:iam::123456789012:role/infra"),
		PropagateTags:         ecstypes.PropagateMITagsCapacityProvider,
		InstanceLaunchTemplate: &ecstypes.InstanceLaunchTemplate{
			Ec2InstanceProfileArn: aws.String("arn:aws:iam::123456789012:instance-profile/x"),
			NetworkConfiguration: &ecstypes.ManagedInstancesNetworkConfiguration{
				Subnets:        []string{"subnet-1", "subnet-2"},
				SecurityGroups: []string{"sg-1"},
			},
			CapacityOptionType: ecstypes.CapacityOptionTypeOnDemand,
			Monitoring:         ecstypes.ManagedInstancesMonitoringOptionsBasic,
			InstanceRequirements: &ecstypes.InstanceRequirementsRequest{
				VCpuCount:                 &ecstypes.VCpuCountRangeRequest{Min: aws.Int32(2), Max: aws.Int32(4)},
				MemoryMiB:                 &ecstypes.MemoryMiBRequest{Min: aws.Int32(2048)},
				AcceleratorTotalMemoryMiB: &ecstypes.AcceleratorTotalMemoryMiBRequest{Min: aws.Int32(1024)},
			},
		},
	}

	cfg, err := Generic(mip, nb.Block, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["infrastructure_role_arn"] != "arn:aws:iam::123456789012:role/infra" {
		t.Errorf("infrastructure_role_arn = %v", cfg["infrastructure_role_arn"])
	}
	ilt, ok := cfg["instance_launch_template"].([]any)
	if !ok || len(ilt) != 1 {
		t.Fatalf("instance_launch_template missing or wrong shape: %#v", cfg["instance_launch_template"])
	}
	iltMap := ilt[0].(map[string]any)
	ir, ok := iltMap["instance_requirements"].([]any)
	if !ok || len(ir) != 1 {
		t.Fatalf("instance_requirements dropped entirely (the VCpu/MiB acronym bug): %#v", iltMap["instance_requirements"])
	}
	irMap := ir[0].(map[string]any)
	vc, ok := irMap["vcpu_count"].([]any)
	if !ok || len(vc) != 1 || vc[0].(map[string]any)["min"] != float64(2) {
		t.Errorf("vcpu_count wrong: %#v", irMap["vcpu_count"])
	}
	mm, ok := irMap["memory_mib"].([]any)
	if !ok || len(mm) != 1 || mm[0].(map[string]any)["min"] != float64(2048) {
		t.Errorf("memory_mib wrong: %#v", irMap["memory_mib"])
	}
	if _, ok := irMap["accelerator_total_memory_mib"]; !ok {
		t.Error("accelerator_total_memory_mib dropped")
	}
}
