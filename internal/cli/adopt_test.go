package cli

import "testing"

func TestRetryableRegex(t *testing.T) {
	yes := []string{
		"Error: error importing: ThrottlingException: Rate exceeded",
		"operation error IAM: ListRoles, https response error StatusCode: 400, RequestLimitExceeded",
		"Too Many Requests",
		"SlowDown: please reduce your request rate",
		"Error: Error acquiring the state lock\n\nError message: resource temporarily unavailable",
	}
	no := []string{
		"Cannot import non-existent remote object",
		"could not parse import ID as ARN: arn: invalid prefix",
		"the provider detected that no object exists with the given id",
	}
	for _, s := range yes {
		if !retryable.MatchString(s) {
			t.Errorf("expected retryable to match: %q", s)
		}
	}
	for _, s := range no {
		if retryable.MatchString(s) {
			t.Errorf("expected retryable NOT to match: %q", s)
		}
	}
}

func TestReadImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/imports.tf", `# header
import {
  to = module.network.aws_vpc.main
  id = "vpc-0abc"
}

import {
  to = module.compute.aws_subnet.private["us-east-1a"]
  id = "subnet-1"
}
`)
	specs, err := readImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2: %+v", len(specs), specs)
	}
	if specs[0].Addr != "module.network.aws_vpc.main" || specs[0].ID != "vpc-0abc" {
		t.Errorf("spec 0 wrong: %+v", specs[0])
	}
	if specs[1].Addr != `module.compute.aws_subnet.private["us-east-1a"]` || specs[1].ID != "subnet-1" {
		t.Errorf("spec 1 wrong: %+v", specs[1])
	}
}
