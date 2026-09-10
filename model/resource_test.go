package model

import "testing"

func TestParseARNAndSplit(t *testing.T) {
	cases := []struct {
		arn                             string
		svc, region, account, rtype, id string
	}{
		{
			"arn:aws:s3:::my-bucket",
			"s3", "", "", "", "my-bucket",
		},
		{
			"arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc",
			"ec2", "us-east-1", "123456789012", "vpc", "vpc-0abc",
		},
		{
			"arn:aws:iam::123456789012:role/path/to/MyRole",
			"iam", "", "123456789012", "role", "path/to/MyRole",
		},
		{
			"arn:aws:dynamodb:eu-west-1:123456789012:table/Orders",
			"dynamodb", "eu-west-1", "123456789012", "table", "Orders",
		},
		{
			"arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/fn:*",
			"logs", "us-east-1", "123456789012", "log-group", "/aws/lambda/fn:*",
		},
	}
	for _, c := range cases {
		_, svc, region, account, resource, ok := ParseARN(c.arn)
		if !ok {
			t.Fatalf("ParseARN(%q) not ok", c.arn)
		}
		rtype, id := SplitResource(resource)
		if svc != c.svc || region != c.region || account != c.account || rtype != c.rtype || id != c.id {
			t.Errorf("%q -> svc=%q region=%q account=%q type=%q id=%q; want %q/%q/%q/%q/%q",
				c.arn, svc, region, account, rtype, id, c.svc, c.region, c.account, c.rtype, c.id)
		}
	}

	if _, _, _, _, _, ok := ParseARN("not-an-arn"); ok {
		t.Error("ParseARN accepted a non-ARN")
	}
}

func TestInventorySummary(t *testing.T) {
	inv := Inventory{Resources: []Resource{
		{Service: "ec2", Type: "vpc"},
		{Service: "ec2", Type: "subnet"},
		{Service: "ec2", Type: "subnet"},
		{Service: "s3", Type: ""},
	}}
	got := inv.CountsByType()
	if got["ec2.subnet"] != 2 || got["ec2.vpc"] != 1 || got["s3"] != 1 {
		t.Fatalf("CountsByType = %v", got)
	}
	sorted := inv.SortedTypeCounts()
	if sorted[0].Type != "ec2.subnet" || sorted[0].Count != 2 {
		t.Fatalf("SortedTypeCounts[0] = %+v", sorted[0])
	}
}
