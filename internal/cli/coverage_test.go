package cli

import (
	"encoding/json"
	"errors"
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
	if r.OtherErrors != 1 {
		t.Errorf("other_errors = %d, want 1 (the gap filler)", r.OtherErrors)
	}
}
