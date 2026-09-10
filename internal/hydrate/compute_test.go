package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
)

func TestEMREbsConfig(t *testing.T) {
	// AWS returns one EbsBlockDevice per actually-attached volume; the real
	// provider groups identical (type, size, iops, throughput) devices into
	// one ebs_config entry with volumes_per_instance set to the count --
	// ebs_config is a Set and volumes_per_instance is part of its hash, so
	// this grouping is required to match what a real Read produces, not
	// just a nicety.
	devs := []emrtypes.EbsBlockDevice{
		{VolumeSpecification: &emrtypes.VolumeSpecification{VolumeType: aws.String("gp3"), SizeInGB: aws.Int32(100)}},
		{VolumeSpecification: &emrtypes.VolumeSpecification{VolumeType: aws.String("gp3"), SizeInGB: aws.Int32(100)}},
		{VolumeSpecification: &emrtypes.VolumeSpecification{VolumeType: aws.String("gp3"), SizeInGB: aws.Int32(500), Iops: aws.Int32(3000)}},
	}

	got := emrEbsConfig(devs)
	if len(got) != 2 {
		t.Fatalf("emrEbsConfig returned %d entries, want 2 (two identical 100GB gp3 volumes collapse into one entry with volumes_per_instance=2), got %+v", len(got), got)
	}

	byKey := map[[2]any]map[string]any{}
	for _, e := range got {
		m := e.(map[string]any)
		byKey[[2]any{m["type"], m["size"]}] = m
	}

	small, ok := byKey[[2]any{"gp3", int32(100)}]
	if !ok {
		t.Fatalf("expected a gp3/100 entry, got %+v", got)
	}
	if small["volumes_per_instance"] != 2 {
		t.Errorf("gp3/100 volumes_per_instance = %v, want 2", small["volumes_per_instance"])
	}

	big, ok := byKey[[2]any{"gp3", int32(500)}]
	if !ok {
		t.Fatalf("expected a gp3/500 entry, got %+v", got)
	}
	if big["volumes_per_instance"] != 1 {
		t.Errorf("gp3/500 volumes_per_instance = %v, want 1", big["volumes_per_instance"])
	}
	if big["iops"] != int32(3000) {
		t.Errorf("gp3/500 iops = %v, want 3000", big["iops"])
	}
}
