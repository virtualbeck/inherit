package discover

import (
	"testing"

	"github.com/virtualbeck/inherit/model"
)

func TestIsEphemeral(t *testing.T) {
	yes := []model.Resource{
		{Service: "ec2", Type: "snapshot"},
		{Service: "ec2", Type: "image"},
		{Service: "rds", Type: "snapshot"},
		{Service: "backup", Type: "recovery-point"},
		{Service: "ssm", Type: "session"},
		{Service: "ec2", Type: "security-group-rule"},
		{Service: "elasticloadbalancing", Type: "listener-rule"},
		{Service: "application-autoscaling", Type: "scalable-target"},
	}
	no := []model.Resource{
		{Service: "ec2", Type: "instance"},
		{Service: "ec2", Type: "vpc"},
		{Service: "rds", Type: "db"},
		{Service: "s3", Type: ""},
	}
	for _, r := range yes {
		if !IsEphemeral(r) {
			t.Errorf("%s.%s should be ephemeral", r.Service, r.Type)
		}
	}
	for _, r := range no {
		if IsEphemeral(r) {
			t.Errorf("%s.%s should not be ephemeral", r.Service, r.Type)
		}
	}
}

func TestFilterResourcesExclude(t *testing.T) {
	res := []model.Resource{
		{Service: "cloudformation", Type: "stack"},
		{Service: "cloudformation", Type: "stackset"},
		{Service: "lambda", Type: "function"},
		{Service: "ec2", Type: "snapshot"}, // also ephemeral
	}

	svc, typ := excludeSet([]string{"CloudFormation"})
	kept, excludedHits := filterResources(res, nil, svc, typ, false)
	if excludedHits != 2 {
		t.Errorf("excludedHits = %d, want 2", excludedHits)
	}
	if len(kept) != 1 || kept[0].Service != "lambda" {
		t.Errorf("kept = %+v, want just the lambda function", kept)
	}

	// no Exclude set: only the ephemeral filter applies
	svc, typ = excludeSet(nil)
	kept, excludedHits = filterResources(res, nil, svc, typ, false)
	if excludedHits != 0 {
		t.Errorf("excludedHits = %d, want 0 with no --exclude", excludedHits)
	}
	if len(kept) != 3 {
		t.Errorf("kept = %d resources, want 3 (snapshot dropped as ephemeral)", len(kept))
	}
}

// service:type entries drop only that one ARN resource-type within a
// service, leaving the rest of that service alone -- the whole point of
// this granularity over a bare service exclude.
func TestFilterResourcesExcludeByType(t *testing.T) {
	res := []model.Resource{
		{Service: "cloudformation", Type: "stack"},
		{Service: "cloudformation", Type: "stackset"},
	}
	svc, typ := excludeSet([]string{"CloudFormation:StackSet"})
	if len(svc) != 0 {
		t.Fatalf("expected no whole-service entries, got %v", svc)
	}
	kept, excludedHits := filterResources(res, nil, svc, typ, false)
	if excludedHits != 1 {
		t.Errorf("excludedHits = %d, want 1", excludedHits)
	}
	if len(kept) != 1 || kept[0].Type != "stack" {
		t.Errorf("kept = %+v, want just the stack", kept)
	}
}

// --services is an allowlist: only listed services survive, everything
// else is dropped regardless of --exclude.
func TestFilterResourcesServicesAllowlist(t *testing.T) {
	res := []model.Resource{
		{Service: "ec2", Type: "instance"},
		{Service: "s3", Type: "bucket"},
		{Service: "lambda", Type: "function"},
	}
	allow := servicesAllowSet([]string{"EC2", "s3"})
	kept, excludedHits := filterResources(res, allow, nil, nil, false)
	if excludedHits != 1 {
		t.Errorf("excludedHits = %d, want 1", excludedHits)
	}
	if len(kept) != 2 {
		t.Errorf("kept = %d resources, want 2 (ec2 + s3)", len(kept))
	}
	for _, r := range kept {
		if r.Service == "lambda" {
			t.Error("lambda should have been dropped by the --services allowlist")
		}
	}
}
