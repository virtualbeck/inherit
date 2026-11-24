package cli

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/virtualbeck/inherit/internal/hydrate"
	"github.com/virtualbeck/inherit/model"
)

func TestCoverageReportHoldsTypeCountsOnly(t *testing.T) {
	inv := model.Inventory{ToolVersion: "v9", Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{ARN: "arn:aws:s3:::secret-bucket-name", TFType: "aws_s3_bucket", Config: map[string]any{"bucket": "secret-bucket-name"}},
			{ARN: "arn:aws:s3:::other", TFType: "aws_s3_bucket", Config: map[string]any{}},
			{ARN: "arn:aws:x:us-east-1:1:y/z", TFType: "aws_probe_nohyd"},
		}}
	st := hydrate.Stats{
		Hydrated:     2,
		NoHydrator:   map[string]int{"aws_probe_nohyd": 1},
		Unmapped:     map[string]int{"zzz.thing": 3},
		ErrorsByType: map[string]int{"aws_probe_err": 2},
		Skipped:      map[string]int{"aws_cloudformation_stack": 5},
		Errors:       []error{errors.New("aws_probe_err a: denied"), errors.New("aws_probe_err b: denied"), errors.New("gap filler: denied")},
	}
	b, err := json.Marshal(coverageReport(inv, st))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, leak := range []string{"secret-bucket-name", "arn:aws", "denied"} {
		if strings.Contains(got, leak) {
			t.Errorf("coverage report leaks %q: %s", leak, got)
		}
	}
	var r struct {
		ToolVersion     string         `json:"tool_version"`
		Account         string         `json:"account"`
		Hydrated        int            `json:"hydrated"`
		HydratedByType  map[string]int `json:"hydrated_by_type"`
		NoHydrator      map[string]int `json:"no_hydrator"`
		Unmapped        map[string]int `json:"unmapped"`
		HydrationErrors map[string]int `json:"hydration_errors"`
		Skipped         map[string]int `json:"skipped"`
		OtherErrors     int            `json:"other_errors"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Account != "123456789012" || r.ToolVersion != "v9" || r.Hydrated != 2 {
		t.Errorf("header = %+v", r)
	}
	if r.HydratedByType["aws_s3_bucket"] != 2 || len(r.HydratedByType) != 1 {
		t.Errorf("hydrated_by_type = %v, want aws_s3_bucket: 2 only", r.HydratedByType)
	}
	if r.NoHydrator["aws_probe_nohyd"] != 1 || r.Unmapped["zzz.thing"] != 3 || r.HydrationErrors["aws_probe_err"] != 2 {
		t.Errorf("gaps = %+v", r)
	}
	if r.Skipped["aws_cloudformation_stack"] != 5 {
		t.Errorf("skipped = %v", r.Skipped)
	}
	if r.OtherErrors != 1 {
		t.Errorf("other_errors = %d, want 1 (the gap filler)", r.OtherErrors)
	}
}

func TestEmittableLeavesBaselineOut(t *testing.T) {
	inv := model.Inventory{Resources: []model.Resource{
		{TFType: "aws_s3_bucket", ID: "app"},
		{TFType: "aws_securityhub_account", ID: "1", Baseline: "account-setting"},
	}}
	if got := emittable(inv, false).Resources; len(got) != 1 || got[0].ID != "app" {
		t.Errorf("emittable = %v, want only the workload", got)
	}
	if got := emittable(inv, true).Resources; len(got) != 2 {
		t.Errorf("--include-baseline must emit everything, got %v", got)
	}
	pruned := model.Inventory{Regions: []string{"us-east-1"}, Resources: []model.Resource{
		{TFType: "aws_securityhub_account", ID: "1", Region: "ca-central-1", Baseline: "account-setting"},
	}}
	if got := emittable(pruned, true).Regions; !slices.Equal(got, []string{"ca-central-1", "us-east-1"}) {
		t.Errorf("--include-baseline must restore a pruned baseline region for its provider alias, got %v", got)
	}
	if len(inv.Resources) != 2 {
		t.Error("emittable must not change the inventory it was given")
	}
}

func TestCoverageCountsBaselinePerType(t *testing.T) {
	inv := model.Inventory{Resources: []model.Resource{
		{TFType: "aws_securityhub_account", Config: map[string]any{}, Baseline: "account-setting"},
		{TFType: "aws_s3_bucket", Config: map[string]any{}},
	}}
	cov := coverageReport(inv, hydrate.Stats{})
	if cov.Baseline["aws_securityhub_account"] != 1 || len(cov.Baseline) != 1 {
		t.Errorf("baseline = %v", cov.Baseline)
	}
}
