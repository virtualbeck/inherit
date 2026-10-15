package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	dlmtypes "github.com/aws/aws-sdk-go-v2/service/dlm/types"
)

func TestDlmTagsToMap(t *testing.T) {
	// raw []Tag shape Generic() leaves behind
	tags := []any{
		map[string]any{"Key": "Environment", "Value": "dev"},
		map[string]any{"Key": "Team", "Value": "platform"},
	}
	got := dlmTagsToMap(tags)
	want := map[string]string{"Environment": "dev", "Team": "platform"}
	if len(got) != len(want) {
		t.Fatalf("dlmTagsToMap(%v) = %v, want %v", tags, got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("dlmTagsToMap(%v)[%q] = %q, want %q", tags, k, got[k], v)
		}
	}

	if got := dlmTagsToMap([]any{map[string]any{"Value": "orphan"}}); len(got) != 0 {
		t.Errorf("expected a keyless tag to be dropped, got %v", got)
	}
}

func TestFixDLMDefaultPolicy(t *testing.T) {
	// regular policy: default_policy must vanish
	cfg := map[string]any{
		"description":    "daily snapshots",
		"policy_details": []any{map[string]any{"resource_types": []any{"VOLUME"}}},
		"default_policy": false,
	}
	fixDLMDefaultPolicy(cfg, []dlmtypes.ResourceTypeValues{dlmtypes.ResourceTypeValuesVolume})
	if _, ok := cfg["default_policy"]; ok {
		t.Errorf("default_policy should be omitted for a regular policy, got %v", cfg["default_policy"])
	}
	if _, ok := cfg["policy_details"]; !ok {
		t.Error("policy_details should survive for a regular (non-default) policy")
	}

	// default policy: enum string, no policy_details
	cfg = map[string]any{
		"policy_details": []any{map[string]any{"resource_types": []any{"INSTANCE"}}},
		"default_policy": true,
	}
	fixDLMDefaultPolicy(cfg, []dlmtypes.ResourceTypeValues{dlmtypes.ResourceTypeValuesInstance})
	if cfg["default_policy"] != "INSTANCE" {
		t.Errorf("default_policy = %v, want the string \"INSTANCE\"", cfg["default_policy"])
	}
	if _, ok := cfg["policy_details"]; ok {
		t.Error("policy_details must not be present alongside default_policy (the provider rejects both together)")
	}
}

func TestDlmSchedules(t *testing.T) {
	// non-nil *0 must not reach config
	cronBased := int32(0)
	retainByCount := int32(0)
	schedules := []dlmtypes.Schedule{
		{
			Name: aws.String("daily-cron"),
			CreateRule: &dlmtypes.CreateRule{
				CronExpression: aws.String("cron(0 0 1 * ? *)"),
				Interval:       &cronBased,
				Location:       dlmtypes.LocationValuesCloud,
			},
			RetainRule: &dlmtypes.RetainRule{
				Count:    aws.Int32(2),
				Interval: &retainByCount,
			},
		},
	}
	got := dlmSchedules(schedules)
	if len(got) != 1 {
		t.Fatalf("dlmSchedules returned %d schedules, want 1", len(got))
	}
	m := got[0].(map[string]any)

	cr := m["create_rule"].(map[string]any)
	if _, ok := cr["interval"]; ok {
		t.Errorf("create_rule.interval = %v, want omitted (cron_expression is set)", cr["interval"])
	}
	if cr["cron_expression"] != "cron(0 0 1 * ? *)" {
		t.Errorf("create_rule.cron_expression = %v, want the cron string", cr["cron_expression"])
	}

	rr := m["retain_rule"].(map[string]any)
	if _, ok := rr["interval"]; ok {
		t.Errorf("retain_rule.interval = %v, want omitted (count is set)", rr["interval"])
	}
	if rr["count"] != int32(2) {
		t.Errorf("retain_rule.count = %v, want 2", rr["count"])
	}

	realInterval := int32(24)
	got = dlmSchedules([]dlmtypes.Schedule{{
		Name: aws.String("hourly-ish"),
		CreateRule: &dlmtypes.CreateRule{
			Interval: &realInterval, IntervalUnit: dlmtypes.IntervalUnitValuesHours,
		},
		RetainRule: &dlmtypes.RetainRule{
			Interval: aws.Int32(30), IntervalUnit: dlmtypes.RetentionIntervalUnitValuesDays,
		},
	}})
	cr = got[0].(map[string]any)["create_rule"].(map[string]any)
	if cr["interval"] != int32(24) {
		t.Errorf("create_rule.interval = %v, want 24", cr["interval"])
	}
	rr = got[0].(map[string]any)["retain_rule"].(map[string]any)
	if rr["interval"] != int32(30) {
		t.Errorf("retain_rule.interval = %v, want 30", rr["interval"])
	}
}
