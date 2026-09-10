package tfschema

import "testing"

func TestLoadAndShape(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Resources) < 1000 {
		t.Fatalf("only %d resource types decoded", len(s.Resources))
	}

	// aws_s3_bucket.tags is a map attribute -> `tags = {}` not a block
	b, ok := s.Resource("aws_s3_bucket")
	if !ok {
		t.Fatal("no aws_s3_bucket")
	}
	tags, ok := b.Attr("tags")
	if !ok || !tags.IsMap() {
		t.Fatalf("aws_s3_bucket.tags not a map attr: %+v", tags)
	}

	// aws_cloudwatch_metric_alarm.dimensions is a map attribute, and
	// metric_query is a repeatable nested block.
	ma, ok := s.Resource("aws_cloudwatch_metric_alarm")
	if !ok {
		t.Fatal("no aws_cloudwatch_metric_alarm")
	}
	dim, ok := ma.Attr("dimensions")
	if !ok || !dim.IsMap() {
		t.Fatalf("dimensions not a map attr: %+v", dim)
	}
	if _, ok := ma.NestedBlock("metric_query"); !ok {
		t.Fatal("metric_query not a nested block")
	}

	// a purely computed attribute is not settable
	vpc, _ := s.Resource("aws_vpc")
	if a, ok := vpc.Attr("dhcp_options_id"); !ok || a.Settable() {
		t.Fatalf("aws_vpc.dhcp_options_id should be computed-only: %+v", a)
	}
	if a, ok := vpc.Attr("cidr_block"); !ok || !a.Settable() {
		t.Fatal("aws_vpc.cidr_block not settable")
	}
}
