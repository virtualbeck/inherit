package emit

import (
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/virtualbeck/inherit/model"
)

func subnet(id, az, cidr, name string, public bool) model.Resource {
	return model.Resource{
		TFType: "aws_subnet", Region: "us-east-1", ID: id,
		ARN:  "arn:aws:ec2:us-east-1:123456789012:subnet/" + id,
		Tags: map[string]string{"Name": name},
		Config: map[string]any{
			"vpc_id":                  "vpc-0aaa1111",
			"availability_zone":       az,
			"cidr_block":              cidr,
			"map_public_ip_on_launch": public,
			"tags":                    map[string]string{"Name": name},
		},
	}
}

func TestForEachConsolidatesSubnets(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			subnet("subnet-01", "us-east-1a", "10.0.1.0/24", "private-1a", false),
			subnet("subnet-02", "us-east-1b", "10.0.2.0/24", "private-1b", false),
			subnet("subnet-03", "us-east-1c", "10.0.3.0/24", "private-1c", false),
		},
	}
	dir := t.TempDir()
	res, err := Write(inv, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	main := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(main, `"private_1a"`) || strings.Contains(main, "private_1b") {
		t.Errorf("per-instance subnet block still emitted:\n%s", main)
	}
	if n := strings.Count(main, `resource "aws_subnet"`); n != 1 {
		t.Fatalf("want 1 aws_subnet block, got %d:\n%s", n, main)
	}
	norm := regexp.MustCompile(` +`).ReplaceAllString(main, " ")
	if !strings.Contains(norm, "for_each = local.private") {
		t.Errorf("no for_each over local map:\n%s", main)
	}
	if !strings.Contains(norm, "availability_zone = each.key") {
		t.Errorf("key attribute not wired to each.key:\n%s", main)
	}
	if !strings.Contains(main, "each.value.cidr_block") {
		t.Errorf("varying attr not wired to each.value:\n%s", main)
	}

	locals := read(t, dir, "modules", "network", "locals.tf")
	for _, k := range []string{`"us-east-1a"`, "10.0.1.0/24", "private-1c"} {
		if !strings.Contains(locals, k) {
			t.Errorf("locals.tf missing %q:\n%s", k, locals)
		}
	}
	if _, d := hclparse.NewParser().ParseHCL([]byte(main), "main.tf"); d.HasErrors() {
		t.Errorf("main.tf does not parse: %s", d)
	}
	if _, d := hclparse.NewParser().ParseHCL([]byte(locals), "locals.tf"); d.HasErrors() {
		t.Errorf("locals.tf does not parse: %s", d)
	}

	// one keyed import block per member
	imp := read(t, dir, "imports.tf")
	got := regexp.MustCompile(`aws_subnet\.private\["[^"]+"\]`).FindAllString(imp, -1)
	if len(got) != 3 {
		t.Errorf("want 3 keyed import blocks, got %d:\n%s", len(got), imp)
	}
	keyed := 0
	for _, s := range res.Imports {
		if strings.Contains(s.Addr, `aws_subnet.private["`) {
			keyed++
		}
	}
	if keyed != 3 {
		t.Errorf("want 3 keyed ImportSpec addrs, got %d", keyed)
	}
}

func TestForEachOptOut(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			subnet("subnet-01", "us-east-1a", "10.0.1.0/24", "private-1a", false),
			subnet("subnet-02", "us-east-1b", "10.0.2.0/24", "private-1b", false),
			subnet("subnet-03", "us-east-1c", "10.0.3.0/24", "private-1c", false),
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{NoForEach: true}); err != nil {
		t.Fatal(err)
	}
	main := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(main, "for_each") {
		t.Errorf("for_each emitted with Options.NoForEach:\n%s", main)
	}
	if n := strings.Count(main, `resource "aws_subnet"`); n != 3 {
		t.Errorf("want 3 separate subnet blocks, got %d", n)
	}
}

func TestForEachRequiresThree(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			subnet("subnet-01", "us-east-1a", "10.0.1.0/24", "private-1a", false),
			subnet("subnet-02", "us-east-1b", "10.0.2.0/24", "private-1b", false),
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	main := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(main, "for_each") {
		t.Errorf("consolidated a run of only 2:\n%s", main)
	}
}

func TestForEachSplitsByStructuralDifference(t *testing.T) {
	// two private + two public: neither run of identical structure reaches 3.
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			subnet("subnet-01", "us-east-1a", "10.0.1.0/24", "private-1a", false),
			subnet("subnet-02", "us-east-1b", "10.0.2.0/24", "private-1b", false),
			subnet("subnet-03", "us-east-1a", "10.0.9.0/24", "public-1a", true),
			subnet("subnet-04", "us-east-1b", "10.0.10.0/24", "public-1b", true),
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	main := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(main, "for_each") {
		t.Errorf("consolidated across a structural (public/private) split:\n%s", main)
	}
}
