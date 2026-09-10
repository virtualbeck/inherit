package awsx

import "testing"

func TestIsReadOnly(t *testing.T) {
	cases := []struct {
		op   string
		want bool
	}{
		{"DescribeInstances", true},
		{"ListBuckets", true},
		{"GetBucketPolicy", true},
		{"BatchGetItem", true},
		{"SelectResourceConfig", true},
		{"LookupEvents", true},
		{"GetCallerIdentity", true},
		{"AssumeRole", true},

		{"RunInstances", false},
		{"CreateBucket", false},
		{"DeleteObject", false},
		{"PutBucketPolicy", false},
		{"TerminateInstances", false},
		{"ModifyVpcAttribute", false},
		{"UpdateStack", false},
		{"TagResources", false},

		// read verb, but has a side effect
		{"GenerateCredentialReport", false},
		{"GetFederationToken", false},

		// bare verb with no capitalised noun after - not matched
		{"Get", false},
		{"List", false},
	}
	for _, c := range cases {
		if got := isReadOnly(c.op); got != c.want {
			t.Errorf("isReadOnly(%q) = %v, want %v", c.op, got, c.want)
		}
	}
}
