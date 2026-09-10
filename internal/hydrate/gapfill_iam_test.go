package hydrate

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestIamTagMap(t *testing.T) {
	got := iamTagMap([]iamtypes.Tag{
		{Key: aws.String("Environment"), Value: aws.String("prod")},
		{Key: aws.String("Team"), Value: aws.String("platform")},
	})
	want := map[string]string{"Environment": "prod", "Team": "platform"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("iamTagMap = %#v, want %#v", got, want)
	}
	if got := iamTagMap(nil); got != nil {
		t.Errorf("iamTagMap(nil) = %#v, want nil", got)
	}
}

func TestIamResourceSegment(t *testing.T) {
	cases := map[string]string{
		"aws_iam_role":     "role",
		"aws_iam_user":     "user",
		"aws_iam_group":    "group",
		"aws_iam_policy":   "policy",
		"aws_iam_whatever": "",
	}
	for tfType, want := range cases {
		if got := iamResourceSegment(tfType); got != want {
			t.Errorf("iamResourceSegment(%q) = %q, want %q", tfType, got, want)
		}
	}
}
