package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { registerGapFiller(gapFillBackupRegionSettings) }

// gapFillBackupRegionSettings discovers the account's per-region Backup
// resource-type opt-in/management preferences: a true singleton (one per
// account per region, DescribeRegionSettings takes no input at all) with no
// ARN or tagging concept, same structural gap as ECR's registry-level
// settings.
func gapFillBackupRegionSettings(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	out, err := backup.NewFromConfig(c.Cfg(region)).DescribeRegionSettings(ctx, &backup.DescribeRegionSettingsInput{})
	if err != nil {
		return nil, nil
	}
	cfg := map[string]any{}
	if v := boolMapToAny(out.ResourceTypeOptInPreference); len(v) > 0 {
		cfg["resource_type_opt_in_preference"] = v
	}
	if v := boolMapToAny(out.ResourceTypeManagementPreference); len(v) > 0 {
		cfg["resource_type_management_preference"] = v
	}
	if len(cfg) == 0 {
		return nil, nil
	}
	return []model.Resource{{
		Service: "backup", Type: "region-settings", TFType: "aws_backup_region_settings",
		Region: region, ID: region, ImportID: region,
		Config: cfg,
	}}, nil
}

// boolMapToAny converts a map[string]bool to map[string]any -- emit's HCL
// writer only recognizes map[string]string/map[string]any for object-typed
// attributes (a hydrator going through Generic()'s JSON round-trip gets this
// for free; this hand-built gap-filler needs it explicit).
func boolMapToAny(m map[string]bool) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
