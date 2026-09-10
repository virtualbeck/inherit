package hydrate

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/virtualbeck/inherit-core/model"
)

// Regression test: genericHydrator with no override silently dropped IAM's
// User/Group "name" attribute entirely, because the SDK structs marshal to
// "user_name"/"group_name", neither of which exists in the schema (both
// resources just call it "name") -- Generic() treats an unknown key as
// unknown-to-schema and drops it, leaving the Required `name` argument unset
// and the generated HCL invalid. genericHydratorOverride must rename it.
func TestGenericHydratorOverrideSetsIAMName(t *testing.T) {
	userFetch := func(ctx context.Context, c *Clients, r model.Resource) (any, error) {
		return iamtypes.User{
			Arn:      aws.String("arn:aws:iam::123456789012:user/alice"),
			UserName: aws.String("alice"),
			Path:     aws.String("/"),
			UserId:   aws.String("AIDAEXAMPLE"),
		}, nil
	}
	h := genericHydratorOverride("aws_iam_user", userFetch, map[string]string{"user_name": "name"})
	cfg, err := h(context.Background(), nil, model.Resource{ID: "alice"})
	if err != nil {
		t.Fatalf("hydrator returned error: %v", err)
	}
	if cfg["name"] != "alice" {
		t.Errorf("aws_iam_user cfg[\"name\"] = %v, want \"alice\" (Required attribute must not be dropped)", cfg["name"])
	}
	if _, ok := cfg["user_name"]; ok {
		t.Error("cfg should not carry a raw \"user_name\" key -- it must be renamed to \"name\", not just added alongside it")
	}

	groupFetch := func(ctx context.Context, c *Clients, r model.Resource) (any, error) {
		return iamtypes.Group{
			Arn:       aws.String("arn:aws:iam::123456789012:group/admins"),
			GroupName: aws.String("admins"),
			Path:      aws.String("/"),
			GroupId:   aws.String("AGPAEXAMPLE"),
		}, nil
	}
	hg := genericHydratorOverride("aws_iam_group", groupFetch, map[string]string{"group_name": "name"})
	gcfg, err := hg(context.Background(), nil, model.Resource{ID: "admins"})
	if err != nil {
		t.Fatalf("hydrator returned error: %v", err)
	}
	if gcfg["name"] != "admins" {
		t.Errorf("aws_iam_group cfg[\"name\"] = %v, want \"admins\" (Required attribute must not be dropped)", gcfg["name"])
	}
}
