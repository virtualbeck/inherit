package hydrate

import "testing"

func TestReplicaTableARN(t *testing.T) {
	cases := []struct {
		home, region, want string
	}{
		{"arn:aws:dynamodb:us-east-1:123456789012:table/my-table", "eu-west-1", "arn:aws:dynamodb:eu-west-1:123456789012:table/my-table"},
		{"not-an-arn", "eu-west-1", ""},
		{"", "eu-west-1", ""},
	}
	for _, c := range cases {
		if got := replicaTableARN(c.home, c.region); got != c.want {
			t.Errorf("replicaTableARN(%q, %q) = %q, want %q", c.home, c.region, got, c.want)
		}
	}
}
