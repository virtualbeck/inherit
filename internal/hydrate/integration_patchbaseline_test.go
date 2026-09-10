package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func TestPatchFilters(t *testing.T) {
	if got := patchFilters(nil); got != nil {
		t.Errorf("patchFilters(nil) = %v, want nil", got)
	}
	g := &ssmtypes.PatchFilterGroup{PatchFilters: []ssmtypes.PatchFilter{
		{Key: ssmtypes.PatchFilterKeyProduct, Values: []string{"AmazonLinux2"}},
		{Key: ssmtypes.PatchFilterKeyClassification, Values: []string{"Security", "Bugfix"}},
	}}
	got := patchFilters(g)
	if len(got) != 2 {
		t.Fatalf("patchFilters returned %d entries, want 2", len(got))
	}
	first := got[0].(map[string]any)
	if first["key"] != "PRODUCT" || len(first["values"].([]any)) != 1 {
		t.Errorf("first filter = %+v, want key PRODUCT with 1 value", first)
	}
}

func TestPatchApprovalRules(t *testing.T) {
	if got := patchApprovalRules(nil); got != nil {
		t.Errorf("patchApprovalRules(nil) = %v, want nil", got)
	}
	g := &ssmtypes.PatchRuleGroup{PatchRules: []ssmtypes.PatchRule{
		{
			ApproveAfterDays: aws.Int32(7),
			ComplianceLevel:  ssmtypes.PatchComplianceLevelCritical,
			PatchFilterGroup: &ssmtypes.PatchFilterGroup{PatchFilters: []ssmtypes.PatchFilter{
				{Key: ssmtypes.PatchFilterKeyClassification, Values: []string{"Security"}},
			}},
		},
		{
			ApproveUntilDate:  aws.String("2026-01-01"),
			EnableNonSecurity: aws.Bool(true),
		},
	}}
	got := patchApprovalRules(g)
	if len(got) != 2 {
		t.Fatalf("patchApprovalRules returned %d entries, want 2", len(got))
	}
	r0 := got[0].(map[string]any)
	if r0["approve_after_days"] != int32(7) {
		t.Errorf("rule 0 approve_after_days = %v, want 7", r0["approve_after_days"])
	}
	if r0["compliance_level"] != "CRITICAL" {
		t.Errorf("rule 0 compliance_level = %v, want CRITICAL", r0["compliance_level"])
	}
	pf, ok := r0["patch_filter"].([]any)
	if !ok || len(pf) != 1 {
		t.Errorf("rule 0 patch_filter = %v, want 1 entry", r0["patch_filter"])
	}
	if _, ok := r0["approve_until_date"]; ok {
		t.Error("rule 0 should not set approve_until_date (mutually exclusive with approve_after_days, not returned by the API for this rule)")
	}

	r1 := got[1].(map[string]any)
	if r1["approve_until_date"] != "2026-01-01" {
		t.Errorf("rule 1 approve_until_date = %v, want 2026-01-01", r1["approve_until_date"])
	}
	if r1["enable_non_security"] != true {
		t.Errorf("rule 1 enable_non_security = %v, want true", r1["enable_non_security"])
	}
	if _, ok := r1["approve_after_days"]; ok {
		t.Error("rule 1 should not set approve_after_days -- the API didn't return it")
	}
}
