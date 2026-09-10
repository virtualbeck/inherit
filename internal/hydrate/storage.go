package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/dlm"
	dlmtypes "github.com/aws/aws-sdk-go-v2/service/dlm/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_s3_bucket", hydrateS3Bucket)
	registerRegionResolver("aws_s3_bucket", resolveS3BucketRegion)
	register("aws_efs_file_system", hydrateEFSFileSystem)
	register("aws_backup_vault", hydrateBackupVault)
	register("aws_backup_plan", hydrateBackupPlan)
	register("aws_dlm_lifecycle_policy", hydrateDLMPolicy)
}

// In provider v5+/v6 almost everything about a bucket (versioning, encryption,
// lifecycle, policy, ...) is a separate aws_s3_bucket_* resource. The bucket
// itself is just its name plus tags; the satellites get their own hydrators
// later.
func hydrateS3Bucket(_ context.Context, _ *Clients, r model.Resource) (map[string]any, error) {
	return map[string]any{"bucket": r.ID}, nil
}

func resolveS3BucketRegion(ctx context.Context, c *Clients, r model.Resource) (string, error) {
	return bucketRegion(ctx, c, r.ID), nil
}

// bucketRegion resolves a bucket's real region: its ARN carries none
// (`arn:aws:s3:::bucket`), so the bucket itself and every aws_s3_bucket_*
// satellite need this to know which region's client -- and, in the generated
// HCL, which aliased provider -- to use.
func bucketRegion(ctx context.Context, c *Clients, bucket string) string {
	base := s3.NewFromConfig(c.Cfg("us-east-1"))
	region := "us-east-1"
	if loc, err := base.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &bucket}); err == nil {
		if r := string(loc.LocationConstraint); r != "" {
			region = r
		}
	}
	return region
}

func hydrateEFSFileSystem(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_efs_file_system")
	if err != nil {
		return nil, err
	}
	cl := efs.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{FileSystemId: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.FileSystems) == 0 {
		return nil, fmt.Errorf("not found")
	}
	// FileSystemProtection/ReplicationOverwriteProtection snake-case to
	// "file_system_protection"/"replication_overwrite_protection", but the
	// schema's nested block and its one attribute are named "protection"/
	// "replication_overwrite" -- Generic() would otherwise drop the whole
	// thing as unrecognized.
	cfg, err := Generic(out.FileSystems[0], sch, map[string]string{
		"file_system_protection":           "protection",
		"replication_overwrite_protection": "replication_overwrite",
	})
	if err != nil {
		return nil, err
	}
	// lifecycle_policy is a separate call the provider reads on every plan.
	if lc, lerr := cl.DescribeLifecycleConfiguration(ctx, &efs.DescribeLifecycleConfigurationInput{FileSystemId: &r.ID}); lerr == nil {
		var pols []any
		for _, p := range lc.LifecyclePolicies {
			pol := map[string]any{}
			if v := string(p.TransitionToIA); v != "" {
				pol["transition_to_ia"] = v
			}
			if v := string(p.TransitionToPrimaryStorageClass); v != "" {
				pol["transition_to_primary_storage_class"] = v
			}
			if v := string(p.TransitionToArchive); v != "" {
				pol["transition_to_archive"] = v
			}
			if len(pol) > 0 {
				pols = append(pols, pol)
			}
		}
		if len(pols) > 0 {
			cfg["lifecycle_policy"] = pols
		}
	}
	return cfg, nil
}

func hydrateBackupVault(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := backup.NewFromConfig(c.Cfg(r.Region)).DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: &r.ID})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.BackupVaultName)}
	if k := aws.ToString(out.EncryptionKeyArn); k != "" {
		cfg["kms_key_arn"] = k
	}
	return cfg, nil
}

func hydrateBackupPlan(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID // backup-plan ARN resource is "backup-plan:<id>"
	if i := strings.LastIndexByte(id, ':'); i >= 0 {
		id = id[i+1:]
	}
	out, err := backup.NewFromConfig(c.Cfg(r.Region)).GetBackupPlan(ctx, &backup.GetBackupPlanInput{BackupPlanId: &id})
	if err != nil {
		return nil, err
	}
	p := out.BackupPlan
	cfg := map[string]any{"name": aws.ToString(p.BackupPlanName)}
	var rules []any
	for _, ru := range p.Rules {
		rule := map[string]any{
			"rule_name":         aws.ToString(ru.RuleName),
			"target_vault_name": aws.ToString(ru.TargetBackupVaultName),
		}
		if v := aws.ToString(ru.ScheduleExpression); v != "" {
			rule["schedule"] = v
		}
		// completion_window/start_window/enable_continuous_backup/
		// recovery_point_tags/schedule_expression_timezone/copy_action:
		// cold_storage_after (transition-to-cold) is one of the more
		// commonly set knobs on a real backup plan.
		if ru.CompletionWindowMinutes != nil {
			rule["completion_window"] = *ru.CompletionWindowMinutes
		}
		if ru.StartWindowMinutes != nil {
			rule["start_window"] = *ru.StartWindowMinutes
		}
		if aws.ToBool(ru.EnableContinuousBackup) {
			rule["enable_continuous_backup"] = true
		}
		if v := aws.ToString(ru.ScheduleExpressionTimezone); v != "" {
			rule["schedule_expression_timezone"] = v
		}
		if len(ru.RecoveryPointTags) > 0 {
			rule["recovery_point_tags"] = ru.RecoveryPointTags
		}
		if v := aws.ToString(ru.TargetLogicallyAirGappedBackupVaultArn); v != "" {
			rule["target_logically_air_gapped_backup_vault_arn"] = v
		}
		if lc := ru.Lifecycle; lc != nil {
			l := map[string]any{}
			if lc.DeleteAfterDays != nil {
				l["delete_after"] = *lc.DeleteAfterDays
			}
			if lc.MoveToColdStorageAfterDays != nil {
				l["cold_storage_after"] = *lc.MoveToColdStorageAfterDays
			}
			if lc.OptInToArchiveForSupportedResources != nil {
				l["opt_in_to_archive_for_supported_resources"] = *lc.OptInToArchiveForSupportedResources
			}
			if len(l) > 0 {
				rule["lifecycle"] = l
			}
		}
		if len(ru.CopyActions) > 0 {
			var cas []any
			for _, ca := range ru.CopyActions {
				cam := map[string]any{"destination_vault_arn": aws.ToString(ca.DestinationBackupVaultArn)}
				if lc := ca.Lifecycle; lc != nil {
					l := map[string]any{}
					if lc.DeleteAfterDays != nil {
						l["delete_after"] = *lc.DeleteAfterDays
					}
					if lc.MoveToColdStorageAfterDays != nil {
						l["cold_storage_after"] = *lc.MoveToColdStorageAfterDays
					}
					if len(l) > 0 {
						cam["lifecycle"] = l
					}
				}
				cas = append(cas, cam)
			}
			rule["copy_action"] = cas
		}
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		cfg["rule"] = rules
	}
	return cfg, nil
}

func hydrateDLMPolicy(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := dlm.NewFromConfig(c.Cfg(r.Region)).GetLifecyclePolicy(ctx, &dlm.GetLifecyclePolicyInput{PolicyId: &r.ID})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_dlm_lifecycle_policy")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.Policy, sch, nil)
	if err != nil {
		return nil, err
	}
	// policy_details.target_tags is map(string) in the schema, but the SDK's
	// PolicyDetails.TargetTags is []Tag{Key,Value} (the standard AWS tag
	// list shape) -- Generic()'s IsMap() handling passes a map(string)
	// attribute's value through completely untouched (it doesn't know how
	// to convert a list-of-{Key,Value} into one), so it arrives as a raw
	// list of {"Key":...,"Value":...} objects instead of a real map.
	if pd, ok := cfg["policy_details"].([]any); ok {
		for _, item := range pd {
			if m, ok := item.(map[string]any); ok {
				if tags, ok := m["target_tags"].([]any); ok {
					m["target_tags"] = dlmTagsToMap(tags)
				}
				// same Generic()/filterNested whole-block-drop failure mode
				// already seen on cloudfront_vpc_origin: create_rule's
				// Required sub-attrs don't all survive pruning, so the
				// entire schedule list came back empty. Built explicitly
				// from the SDK struct instead of trusting Generic() here.
				if sch := dlmSchedules(out.Policy.PolicyDetails.Schedules); len(sch) > 0 {
					m["schedule"] = sch
				}
			}
		}
	}
	fixDLMDefaultPolicy(cfg, out.Policy.PolicyDetails.ResourceTypes)
	return cfg, nil
}

func dlmSchedules(schedules []dlmtypes.Schedule) []any {
	var out []any
	for _, s := range schedules {
		m := map[string]any{"name": aws.ToString(s.Name)}
		if s.CopyTags != nil {
			m["copy_tags"] = *s.CopyTags
		}
		if len(s.TagsToAdd) > 0 {
			m["tags_to_add"] = dlmTagsToMap(dlmTagsToAny(s.TagsToAdd))
		}
		if len(s.VariableTags) > 0 {
			m["variable_tags"] = dlmTagsToMap(dlmTagsToAny(s.VariableTags))
		}
		if cr := s.CreateRule; cr != nil {
			crm := map[string]any{}
			if v := aws.ToString(cr.CronExpression); v != "" {
				crm["cron_expression"] = v
			}
			// create_rule is exactly one of cron_expression or
			// interval+interval_unit, but the SDK always returns Interval
			// as a non-nil *0, not nil, on a cron-scheduled policy -- 0
			// isn't in the schema's allowed enum ([1 2 3 4 6 8 12 24]), so
			// only set it when it's actually meaningful.
			if cr.Interval != nil && *cr.Interval != 0 {
				crm["interval"] = *cr.Interval
			}
			if v := string(cr.IntervalUnit); v != "" {
				crm["interval_unit"] = v
			}
			if v := string(cr.Location); v != "" {
				crm["location"] = v
			}
			if len(cr.Times) > 0 {
				crm["times"] = toAny(cr.Times)
			}
			m["create_rule"] = crm
		}
		if rr := s.RetainRule; rr != nil {
			rrm := map[string]any{}
			if rr.Count != nil {
				rrm["count"] = *rr.Count
			}
			// same story as create_rule above: Interval comes back non-nil
			// *0 on a count-based retain rule, and 0 fails the schema's
			// "at least 1" check.
			if rr.Interval != nil && *rr.Interval != 0 {
				rrm["interval"] = *rr.Interval
			}
			if v := string(rr.IntervalUnit); v != "" {
				rrm["interval_unit"] = v
			}
			m["retain_rule"] = rrm
		}
		out = append(out, m)
	}
	return out
}

// dlmTagsToAny adapts the SDK's []Tag straight to dlmTagsToMap's []any
// input (which normally comes from Generic()'s JSON round-trip) without a
// second, parallel map-building helper.
func dlmTagsToAny(tags []dlmtypes.Tag) []any {
	out := make([]any, 0, len(tags))
	for _, t := range tags {
		out = append(out, map[string]any{"Key": aws.ToString(t.Key), "Value": aws.ToString(t.Value)})
	}
	return out
}

// fixDLMDefaultPolicy corrects default_policy in place. It's a string enum
// ("VOLUME"/"INSTANCE") identifying one of AWS's own pre-built default
// policies -- and conflicts outright with policy_details, which only
// applies to a regular custom policy. DLM's SDK models it as a bare
// DefaultPolicy *bool, which Generic() marshals straight through as a JSON
// bool; that satisfies neither the enum-string type nor the mutual
// exclusion. The overwhelming common case is false (a regular policy): just
// omit the attribute entirely -- its presence at all is what triggers the
// conflict, not its value.
func fixDLMDefaultPolicy(cfg map[string]any, resourceTypes []dlmtypes.ResourceTypeValues) {
	isDefault, ok := cfg["default_policy"].(bool)
	if !ok {
		return
	}
	delete(cfg, "default_policy")
	if !isDefault {
		return
	}
	delete(cfg, "policy_details")
	kind := dlmtypes.ResourceTypeValuesVolume
	if len(resourceTypes) > 0 {
		kind = resourceTypes[0]
	}
	cfg["default_policy"] = string(kind)
}

func dlmTagsToMap(tags []any) map[string]string {
	m := map[string]string{}
	for _, t := range tags {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		k, _ := tm["Key"].(string)
		v, _ := tm["Value"].(string)
		if k != "" {
			m[k] = v
		}
	}
	return m
}
