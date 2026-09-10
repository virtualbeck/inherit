package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bktypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestGuarddutyCriterion(t *testing.T) {
	gt := int64(30)
	m := map[string]gdtypes.Condition{
		"severity": {Equals: []string{"7", "8"}, GreaterThan: &gt},
	}
	got := guarddutyCriterion(m)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	c := got[0].(map[string]any)
	if c["field"] != "severity" {
		t.Errorf("field = %v, want severity", c["field"])
	}
	if c["greater_than"] != "30" {
		t.Errorf("greater_than = %v (%T), want string \"30\" -- the schema wants a string, not the SDK's int64", c["greater_than"], c["greater_than"])
	}
	eq, ok := c["equals"].([]any)
	if !ok || len(eq) != 2 {
		t.Errorf("equals = %v, want 2 entries", c["equals"])
	}

	// deprecated fields (Gt/Gte/Lt/Lte/Eq/Neq) must never surface -- only
	// their non-deprecated replacements are read.
	deprecated := map[string]gdtypes.Condition{
		"port": {Gt: aws.Int32(80)},
	}
	got2 := guarddutyCriterion(deprecated)
	c2 := got2[0].(map[string]any)
	if _, ok := c2["greater_than"]; ok {
		t.Error("deprecated Gt field should not produce greater_than")
	}
}

func TestBackupSelectionCondition(t *testing.T) {
	c := &bktypes.Conditions{
		StringEquals: []bktypes.ConditionParameter{
			{ConditionKey: aws.String("aws:ResourceTag/env"), ConditionValue: aws.String("prod")},
		},
	}
	got := backupSelectionCondition(c)
	se, ok := got["string_equals"].([]any)
	if !ok || len(se) != 1 {
		t.Fatalf("string_equals = %v, want 1 entry", got["string_equals"])
	}
	entry := se[0].(map[string]any)
	if entry["key"] != "aws:ResourceTag/env" || entry["value"] != "prod" {
		t.Errorf("entry = %v", entry)
	}
	if _, ok := got["string_like"]; ok {
		t.Error("empty StringLike should not appear in output at all")
	}

	if got := backupSelectionCondition(&bktypes.Conditions{}); got != nil {
		t.Errorf("all-empty Conditions should return nil, got %v", got)
	}
	if got := backupSelectionCondition(nil); got != nil {
		t.Errorf("nil Conditions should return nil, got %v", got)
	}
}

func TestBackupSelectionTags(t *testing.T) {
	cs := []bktypes.Condition{
		{ConditionKey: aws.String("backup"), ConditionType: bktypes.ConditionTypeStringequals, ConditionValue: aws.String("daily")},
	}
	got := backupSelectionTags(cs)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	m := got[0].(map[string]any)
	if m["key"] != "backup" || m["value"] != "daily" || m["type"] != "STRINGEQUALS" {
		t.Errorf("entry = %v", m)
	}
}

func TestS3ACLConfig(t *testing.T) {
	owner := &s3types.Owner{ID: aws.String("owner-id"), DisplayName: aws.String("me")}
	grants := []s3types.Grant{
		{Permission: s3types.PermissionFullControl, Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: aws.String("owner-id")}},
	}
	got := s3ACLConfig(owner, grants)
	acp, ok := got["access_control_policy"].([]any)
	if !ok || len(acp) != 1 {
		t.Fatalf("access_control_policy = %v", got["access_control_policy"])
	}
	block := acp[0].(map[string]any)
	ownerBlock := block["owner"].([]any)[0].(map[string]any)
	if ownerBlock["id"] != "owner-id" || ownerBlock["display_name"] != "me" {
		t.Errorf("owner = %v", ownerBlock)
	}
	grantList := block["grant"].([]any)
	if len(grantList) != 1 {
		t.Fatalf("got %d grants, want 1", len(grantList))
	}

	// a bucket with an enforced ownership setting (no real grants beyond
	// what GetBucketAcl always returns for the owner) should still produce
	// something -- only a genuinely nil owner (an error path) returns nil.
	if got := s3ACLConfig(nil, nil); got != nil {
		t.Errorf("nil owner should return nil, got %v", got)
	}
	if got := s3ACLConfig(owner, nil); got != nil {
		t.Errorf("owner with zero grants should return nil (nothing recoverable), got %v", got)
	}
}

func TestS3TieringFilter(t *testing.T) {
	f := &s3types.IntelligentTieringFilter{
		Prefix: aws.String("logs/"),
		And: &s3types.IntelligentTieringAndOperator{
			Tags: []s3types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}},
		},
	}
	got := s3TieringFilter(f)
	if got["prefix"] != "logs/" {
		t.Errorf("prefix = %v, want logs/", got["prefix"])
	}
	tags, ok := got["tags"].(map[string]string)
	if !ok || tags["team"] != "platform" {
		t.Errorf("tags = %v, want team=platform (merged in from the And operator, not dropped)", got["tags"])
	}

	if got := s3TieringFilter(nil); got != nil {
		t.Errorf("nil filter should return nil, got %v", got)
	}
}
