package emit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/virtualbeck/inherit/model"
)

func read(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteBackendEnvironmentAware(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1",
				Config: map[string]any{"cidr_block": "10.0.0.0/16", "instance_tenancy": "default"}},
		},
	}

	flat := t.TempDir()
	if _, err := Write(inv, flat, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, flat, "backend.tf"); !strings.Contains(got, `key          = "123456789012/terraform.tfstate"`) {
		t.Errorf("flat-mode backend.tf missing the real account id in its example key:\n%s", got)
	}

	env := t.TempDir()
	if _, err := Write(inv, env, Options{Environment: "dev"}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, env, "backend.tf"); !strings.Contains(got, `key          = "123456789012/dev/terraform.tfstate"`) {
		t.Errorf("environment-mode backend.tf missing the account+environment example key:\n%s", got)
	}
}

// A tag identical on every taggable resource is safe to lift into the
// provider's default_tags; anything not identical everywhere (a resource
// missing it, or holding a different value) must stay put -- default_tags
// has no per-resource opt-out, so anything less than "everyone already
// matches" would change a real resource's effective tags.
func TestWriteDefaultTags(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1",
				Tags: map[string]string{"Environment": "prod", "Team": "platform", "Name": "main-vpc"},
				Config: map[string]any{"cidr_block": "10.0.0.0/16",
					"tags": map[string]string{"Environment": "prod", "Team": "platform", "Name": "main-vpc"}}},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-1",
				Tags: map[string]string{"Environment": "prod", "Team": "platform", "Name": "web-sg"},
				Config: map[string]any{"name": "web", "vpc_id": "vpc-1",
					"tags": map[string]string{"Environment": "prod", "Team": "platform", "Name": "web-sg"}}},
			// Team differs here -- must NOT be hoisted despite matching on the
			// other two resources.
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-2",
				Tags: map[string]string{"Environment": "prod", "Team": "data", "Name": "db-sg"},
				Config: map[string]any{"name": "db", "vpc_id": "vpc-1",
					"tags": map[string]string{"Environment": "prod", "Team": "data", "Name": "db-sg"}}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	prov := read(t, dir, "providers.tf")
	if !regexp.MustCompile(`default_tags\s*\{\s*tags\s*=\s*\{\s*Environment\s*=\s*"prod"\s*\}`).MatchString(prov) {
		t.Errorf("providers.tf missing default_tags with just Environment:\n%s", prov)
	}
	if strings.Contains(prov, "Team") || strings.Contains(prov, "platform") {
		t.Errorf("providers.tf hoisted a non-universal tag:\n%s", prov)
	}

	net := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(net, `"prod"`) {
		t.Errorf("network module still carries the hoisted Environment tag value on a resource:\n%s", net)
	}
	if !strings.Contains(net, `"main-vpc"`) {
		t.Errorf("network module lost its resource-specific Name tag:\n%s", net)
	}
	if !strings.Contains(net, `Team`) {
		t.Errorf("network module lost the non-universal Team tag entirely:\n%s", net)
	}
}

func TestWriteExternalRefHoisting(t *testing.T) {
	// two security groups pointing at the SAME foreign (undiscovered) VPC --
	// should share one bare "vpc_id" variable, not mint one each.
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-1", Tags: map[string]string{"Name": "web"},
				Config: map[string]any{"name": "web", "description": "web", "vpc_id": "vpc-ba627dde"}},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-2", Tags: map[string]string{"Name": "db"},
				Config: map[string]any{"name": "db", "description": "db", "vpc_id": "vpc-ba627dde",
					"vpc_security_group_ids": []any{"sg-external-1", "sg-external-2"}}},
			// a third, unrelated VPC id -- must NOT share the "vpc_id" name
			// with the two above (a real conflict, needs its own variable).
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-3", Tags: map[string]string{"Name": "other"},
				Config: map[string]any{"name": "other", "description": "other", "vpc_id": "vpc-deadbeef"}},
		},
	}

	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	vars := read(t, dir, "modules", "network", "variables.tf")
	if !strings.Contains(vars, `variable "vpc_id"`) {
		t.Fatalf("expected a shared, bare \"vpc_id\" variable, got:\n%s", vars)
	}
	if strings.Contains(vars, "default") && strings.Contains(vars, `variable "vpc_id" {`) {
		// crude but sufficient: the vpc_id block specifically must have no default.
		idx := strings.Index(vars, `variable "vpc_id" {`)
		block := vars[idx : idx+strings.Index(vars[idx:], "}")]
		if strings.Contains(block, "default") {
			t.Errorf("vpc_id must be a required variable (no default), got:\n%s", block)
		}
	}
	if !strings.Contains(vars, `type        = string`) && !strings.Contains(vars, "type = string") {
		t.Errorf("vpc_id should be typed string, got:\n%s", vars)
	}
	if !strings.Contains(vars, `type        = list(string)`) && !strings.Contains(vars, "type = list(string)") {
		t.Errorf("vpc_security_group_ids should be typed list(string), got:\n%s", vars)
	}
	if !strings.Contains(vars, "other_vpc_id") {
		t.Errorf("the conflicting third VPC id should get its own prefixed variable, got:\n%s", vars)
	}

	main := read(t, dir, "modules", "network", "main.tf")
	if strings.Contains(main, `"vpc-ba627dde"`) || strings.Contains(main, `"vpc-deadbeef"`) {
		t.Errorf("literal foreign VPC ids should never appear in the module's own main.tf, got:\n%s", main)
	}
	if !strings.Contains(main, "var.vpc_id") {
		t.Errorf("expected var.vpc_id in the module body, got:\n%s", main)
	}

	root := read(t, dir, "main.tf")
	if !regexp.MustCompile(`vpc_id\s+= "vpc-ba627dde"`).MatchString(root) {
		t.Errorf("root main.tf should supply the literal vpc_id explicitly, got:\n%s", root)
	}
	if !strings.Contains(root, "vpc-deadbeef") {
		t.Errorf("root main.tf should also supply the conflicting other_vpc_id, got:\n%s", root)
	}
}

func TestWriteModuleLayout(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012",
		Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1", ARN: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1",
				Tags:   map[string]string{"Name": "main vpc"},
				Config: map[string]any{"cidr_block": "10.0.0.0/16", "instance_tenancy": "default", "tags": map[string]string{"Name": "main vpc"}}},
			{TFType: "aws_subnet", Region: "us-east-1", ID: "subnet-1",
				Config: map[string]any{"vpc_id": "vpc-1", "cidr_block": "10.0.1.0/24"}},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-1", Tags: map[string]string{"Name": "web"},
				Config: map[string]any{"name": "web", "description": "web", "vpc_id": "vpc-1"}},
			{TFType: "aws_s3_bucket", Region: "us-east-1", ID: "my-bucket",
				Config: map[string]any{"bucket": "my-bucket"}},
			// cross-module: database resource pointing at a network security group
			{TFType: "aws_db_instance", Region: "us-east-1", ID: "db-1",
				Config: map[string]any{"identifier": "db-1", "engine": "postgres", "instance_class": "db.t3.micro",
					"vpc_security_group_ids": []any{"sg-1"}}},
		},
	}

	dir := t.TempDir()
	res, err := Write(inv, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocks != 5 {
		t.Fatalf("wrote %d blocks, want 5", res.Blocks)
	}

	// every generated .tf parses
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.HasSuffix(p, ".tf") {
			b, _ := os.ReadFile(p)
			if _, diag := hclparse.NewParser().ParseHCL(b, p); diag.HasErrors() {
				t.Errorf("%s does not parse: %s", p, diag)
			}
		}
		return nil
	})

	// vpc/subnet/sg are each the only one of their type in the network
	// module -> each is "main" (different Terraform types, no collision).
	net := read(t, dir, "modules", "network", "main.tf")
	if !strings.Contains(net, `resource "aws_vpc" "main"`) || !strings.Contains(net, `resource "aws_security_group" "main"`) {
		t.Errorf("network module missing resources:\n%s", net)
	}
	// same-category ref stays direct
	if !regexp.MustCompile(`vpc_id\s*=\s*aws_vpc\.main\.id`).MatchString(net) {
		t.Errorf("subnet vpc_id not a direct ref:\n%s", net)
	}

	// cross-category ref: db (database) -> sg (network)
	db := read(t, dir, "modules", "database", "main.tf")
	if !regexp.MustCompile(`var\.network_main_id`).MatchString(db) {
		t.Errorf("db instance not wired to a module input:\n%s", db)
	}
	netOut := read(t, dir, "modules", "network", "outputs.tf")
	if !strings.Contains(netOut, `output "main_id"`) || !strings.Contains(netOut, "aws_security_group.main.id") {
		t.Errorf("network module missing main_id output:\n%s", netOut)
	}
	dbVars := read(t, dir, "modules", "database", "variables.tf")
	if !strings.Contains(dbVars, `variable "network_main_id"`) {
		t.Errorf("database module missing network_main_id variable:\n%s", dbVars)
	}
	if strings.Contains(dbVars, `type        = "string"`) || !strings.Contains(dbVars, "type        = string") {
		t.Errorf("variable type constraint must be a bare identifier, not quoted:\n%s", dbVars)
	}
	rootMain := read(t, dir, "main.tf")
	if !strings.Contains(rootMain, `module "network"`) || !strings.Contains(rootMain, `module "database"`) ||
		!strings.Contains(rootMain, "network_main_id = module.network.main_id") {
		t.Errorf("root main.tf wiring wrong:\n%s", rootMain)
	}

	imports := read(t, dir, "imports.tf")
	if !strings.Contains(imports, "to = module.network.aws_vpc.main") || !strings.Contains(imports, `id = "vpc-1"`) {
		t.Errorf("imports.tf not module-qualified:\n%s", imports)
	}
	if len(res.Imports) != 5 || res.Imports[0].Addr == "" {
		t.Errorf("import specs: %+v", res.Imports)
	}

	prov := read(t, dir, "providers.tf")
	if !strings.Contains(prov, `region = "us-east-1"`) {
		t.Errorf("providers.tf region missing:\n%s", prov)
	}

	// standard-structure extras
	if !strings.Contains(read(t, dir, "README.md"), "## Layout") {
		t.Error("root README.md missing")
	}
	if !strings.Contains(read(t, dir, "backend.tf"), `backend "s3"`) {
		t.Error("backend.tf skeleton missing")
	}
	if !strings.Contains(read(t, dir, "modules", "network", "README.md"), "aws_vpc") {
		t.Error("module README.md missing or lacks resource types")
	}
	if !strings.Contains(dbVars, "description") {
		t.Errorf("module variables missing descriptions:\n%s", dbVars)
	}
	if !strings.Contains(netOut, "description") {
		t.Errorf("module outputs missing descriptions:\n%s", netOut)
	}
}

// A resource outside the provider's default region needs its own `region`
// argument (provider v6 per-resource override), or every AWS call for it --
// import included -- goes to the default region's endpoint and 404s.
func TestWriteCrossRegionAttribute(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012",
		Regions: []string{"us-east-1", "us-west-2"},
		Resources: []model.Resource{
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1", ARN: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1",
				Config: map[string]any{"cidr_block": "10.0.0.0/16"}},
			{TFType: "aws_vpc", Region: "us-west-2", ID: "vpc-2", ARN: "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-2",
				Config: map[string]any{"cidr_block": "10.1.0.0/16"}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	net := read(t, dir, "modules", "network", "main.tf")
	// two untagged, non-sole VPCs -> deterministic hash names (vpc_<hex>).
	blocks := regexp.MustCompile(`(?s)resource "aws_vpc" "vpc_[0-9a-f]+" \{.*?\n\}`).FindAllString(net, -1)
	if len(blocks) != 2 {
		t.Fatalf("expected two vpc blocks, got %d in:\n%s", len(blocks), net)
	}
	// exactly one of the two carries a provider override -- whichever isn't
	// the (majority-vote) default region -- never both, never neither. A
	// schema `region` attribute isn't enough: it isn't consulted by the
	// provider's ImportResourceState RPC, only a `provider = aws.<alias>`
	// meta-argument (resolved before any RPC) reliably routes both import
	// and ordinary reads/writes to the right region.
	withProvider := 0
	for _, b := range blocks {
		if strings.Contains(b, "provider") {
			withProvider++
			if !regexp.MustCompile(`provider\s*=\s*aws\.us_west_2`).MatchString(b) {
				t.Errorf("the aliased vpc's provider argument is wrong:\n%s", b)
			}
		}
	}
	if withProvider != 1 {
		t.Errorf("expected exactly one vpc to carry a provider argument, got %d:\n%s", withProvider, net)
	}

	// the aliased provider itself must exist in the root, pinned to that region
	prov := read(t, dir, "providers.tf")
	if !regexp.MustCompile(`provider "aws" \{\s*alias\s*=\s*"us_west_2"\s*\n\s*region\s*=\s*"us-west-2"`).MatchString(prov) {
		t.Errorf("providers.tf missing the aliased us_west_2 provider:\n%s", prov)
	}

	// the network module must declare the alias and the root must pass it in
	modProv := read(t, dir, "modules", "network", "versions.tf")
	if !strings.Contains(modProv, "configuration_aliases") || !strings.Contains(modProv, "aws.us_west_2") {
		t.Errorf("network module versions.tf missing configuration_aliases:\n%s", modProv)
	}
	rootMain := read(t, dir, "main.tf")
	if !regexp.MustCompile(`providers\s*=\s*\{[^}]*aws\.us_west_2\s*=\s*aws\.us_west_2`).MatchString(rootMain) {
		t.Errorf("root main.tf missing providers passthrough for network module:\n%s", rootMain)
	}
}

// Two distinct resources that happen to share a bare ID (the same name reused
// in different regions) must never wire a literal that merely matches that ID
// into a reference -- there's no way to tell which of the two was meant, and
// picking one silently rewires the other's config to point at it.
func TestWireValueAmbiguousIDNotReferenced(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012",
		Regions: []string{"us-west-1", "us-west-2"},
		Resources: []model.Resource{
			{TFType: "aws_sns_topic", Region: "us-west-1", ID: "shared-name",
				ARN:    "arn:aws:sns:us-west-1:123456789012:shared-name",
				Config: map[string]any{"name": "shared-name"}},
			{TFType: "aws_sns_topic", Region: "us-west-2", ID: "shared-name",
				ARN:    "arn:aws:sns:us-west-2:123456789012:shared-name",
				Config: map[string]any{"name": "shared-name"}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	integ := read(t, dir, "modules", "integration", "main.tf")
	if strings.Contains(integ, "aws_sns_topic.shared_name.id") || strings.Contains(integ, "aws_sns_topic.shared_name_2.id") {
		t.Errorf("ambiguous ID got wired into a cross-resource reference:\n%s", integ)
	}
	vars := read(t, dir, "modules", "integration", "variables.tf")
	if n := len(regexp.MustCompile(`default\s*=\s*"shared-name"`).FindAllString(vars, -1)); n != 2 {
		t.Errorf("both topics should keep their own literal name, not reference each other (found %d):\n%s", n, vars)
	}
}

// AWS auto-creates a Cloud Map namespace for ECS Service Connect using the
// cluster's own ID as the namespace's "name" -- confirmed against a real
// account. That's a plain display string on
// aws_service_discovery_http_namespace, not a link back to the cluster;
// wiring it as one produced a real module.compute <-> module.other cycle
// (compute legitimately depends on other for the namespace ARN via
// service_connect_defaults.namespace).
func TestWireValueServiceDiscoveryNameNotReferenced(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012",
		Regions: []string{"us-west-2"},
		Resources: []model.Resource{
			{TFType: "aws_ecs_cluster", Region: "us-west-2", ID: "cluster-xyz",
				ARN: "arn:aws:ecs:us-west-2:123456789012:cluster/xyz",
				Config: map[string]any{"name": "xyz", "service_connect_defaults": map[string]any{
					"namespace": "arn:aws:servicediscovery:us-west-2:123456789012:namespace/ns-xyz",
				}}},
			{TFType: "aws_service_discovery_http_namespace", Region: "us-west-2", ID: "ns-xyz",
				ARN:    "arn:aws:servicediscovery:us-west-2:123456789012:namespace/ns-xyz",
				Config: map[string]any{"name": "cluster-xyz"}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	vars := read(t, dir, "modules", "other", "variables.tf")
	if !regexp.MustCompile(`default\s*=\s*"cluster-xyz"`).MatchString(vars) {
		t.Errorf("namespace's own \"name\" should hoist as a literal default, not stay unset:\n%s", vars)
	}
	rootMain := read(t, dir, "main.tf")
	otherBlock := regexp.MustCompile(`module "other" \{[^}]*\}`).FindString(rootMain)
	if strings.Contains(otherBlock, "module.compute") {
		t.Errorf("module.other should not take an input wired from module.compute -- that's the cycle:\n%s", rootMain)
	}
}

// Cross-module references into a §5.3 for_each group must share ONE output
// (a `for` expression over the whole group) rather than minting a separate
// single-key output per referenced member. Confirmed against a real
// account: three subnets in one for_each group, each referenced once from
// another module, produced three near-identical outputs
// (public_10_1_252_0_24_id, _253_, _254_) -- exactly the duplication §5.3
// already collapses on the locals side, just not on the outputs side.
func TestForEachCrossModuleRefSharesOneOutput(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			subnet("subnet-01", "us-east-1a", "10.0.1.0/24", "private-1a", false),
			subnet("subnet-02", "us-east-1b", "10.0.2.0/24", "private-1b", false),
			subnet("subnet-03", "us-east-1c", "10.0.3.0/24", "private-1c", false),
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-001",
				ARN:    "arn:aws:ec2:us-east-1:123456789012:instance/i-001",
				Config: map[string]any{"ami": "ami-1", "instance_type": "t3.micro", "subnet_id": "subnet-01"}},
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-002",
				ARN:    "arn:aws:ec2:us-east-1:123456789012:instance/i-002",
				Config: map[string]any{"ami": "ami-1", "instance_type": "t3.micro", "subnet_id": "subnet-02"}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	netOut := read(t, dir, "modules", "network", "outputs.tf")
	if n := strings.Count(netOut, `output "private_ids"`); n != 1 {
		t.Errorf("want exactly 1 consolidated output, got %d:\n%s", n, netOut)
	}
	if !regexp.MustCompile(`\{\s*for k, v in aws_subnet\.private\s*:\s*k => v\.id\s*\}`).MatchString(netOut) {
		t.Errorf("output value should be a for expression over the whole group:\n%s", netOut)
	}
	if _, d := hclparse.NewParser().ParseHCL([]byte(netOut), "outputs.tf"); d.HasErrors() {
		t.Errorf("outputs.tf does not parse: %s", d)
	}

	// consolidate() picks whichever attribute actually differentiates the
	// group as its for_each key (here availability_zone) -- not the
	// resource's own ID, so that's what each instance indexes by.
	compute := read(t, dir, "modules", "compute", "main.tf")
	if !strings.Contains(compute, `var.network_private_ids["us-east-1a"]`) ||
		!strings.Contains(compute, `var.network_private_ids["us-east-1b"]`) {
		t.Errorf("both instances should index the same map var by their own key:\n%s", compute)
	}

	computeVars := read(t, dir, "modules", "compute", "variables.tf")
	if n := strings.Count(computeVars, `variable "network_private_ids"`); n != 1 {
		t.Errorf("want exactly 1 consolidated input variable, got %d:\n%s", n, computeVars)
	}
	if !strings.Contains(computeVars, "map(string)") {
		t.Errorf("consolidated var should be typed map(string):\n%s", computeVars)
	}

	rootMain := read(t, dir, "main.tf")
	if n := strings.Count(rootMain, "network_private_ids = module.network.private_ids"); n != 1 {
		t.Errorf("want exactly 1 root wire for the consolidated var, got %d:\n%s", n, rootMain)
	}
}

// Three different for_each-consolidated resource types can legitimately
// share the same resource block NAME within one module (Terraform
// addresses are type-qualified: aws_iam_group_policy_attachment.policy and
// aws_iam_role_policy_attachment.policy don't collide) -- but a `locals {}`
// block is flat, not type-qualified. Confirmed against a real account:
// three IAM policy-attachment types (group/role/user) all named "policy"
// (groupBaseName hardcodes this) reduced to a single local.policy holding
// only the last-written type's shape, so the other two for_each'd over
// data with the wrong attributes entirely (each.value.group /
// each.value.role referencing keys that simply didn't exist), failing
// `terraform validate` outright.
func TestForEachLocalNameDedupedAcrossTypes(t *testing.T) {
	mkAttachments := func(tfType string, n int, cfg func(i int) map[string]any) []model.Resource {
		var rs []model.Resource
		for i := range n {
			rs = append(rs, model.Resource{
				TFType: tfType, Region: "us-east-1",
				ID:     fmt.Sprintf("%s-%d", tfType, i),
				ARN:    fmt.Sprintf("arn:aws:iam::123456789012:%s/%d", tfType, i),
				Config: cfg(i),
			})
		}
		return rs
	}
	var resources []model.Resource
	resources = append(resources, mkAttachments("aws_iam_group_policy_attachment", 3, func(i int) map[string]any {
		return map[string]any{"group": fmt.Sprintf("g%d", i), "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
	})...)
	resources = append(resources, mkAttachments("aws_iam_role_policy_attachment", 3, func(i int) map[string]any {
		return map[string]any{"role": fmt.Sprintf("r%d", i), "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
	})...)
	resources = append(resources, mkAttachments("aws_iam_user_policy_attachment", 3, func(i int) map[string]any {
		return map[string]any{"user": fmt.Sprintf("u%d", i), "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
	})...)

	inv := model.Inventory{Account: "123456789012", Regions: []string{"us-east-1"}, Resources: resources}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	locals := read(t, dir, "modules", "security", "locals.tf")
	if n := strings.Count(locals, "policy"); n < 3 {
		// each local name should appear at least once as a declaration
		t.Errorf("expected 3 distinct locals for 3 different policy-attachment types, got locals.tf:\n%s", locals)
	}

	main := read(t, dir, "modules", "security", "main.tf")
	forEachRefs := regexp.MustCompile(`for_each\s*=\s*local\.(\S+)`).FindAllStringSubmatch(main, -1)
	if len(forEachRefs) != 3 {
		t.Fatalf("want 3 for_each blocks, got %d:\n%s", len(forEachRefs), main)
	}
	seen := map[string]bool{}
	for _, m := range forEachRefs {
		seen[m[1]] = true
	}
	if len(seen) != 3 {
		t.Errorf("all 3 for_each blocks reference the SAME local -- the exact bug this guards against: %v\n%s", seen, main)
	}

	// each.value attribute access must match the resource type it's actually on.
	// (?s) + non-greedy: [^}]* would wrongly stop at the literal "}" closing
	// the ${...} interpolation in policy_arn, well before the block's own end.
	if !regexp.MustCompile(`(?s)"aws_iam_group_policy_attachment"\s+"policy"\s*\{.*?each\.value\.group.*?\n\}`).MatchString(main) {
		t.Errorf("group attachment should read each.value.group:\n%s", main)
	}
	if !regexp.MustCompile(`(?s)"aws_iam_role_policy_attachment"\s+"policy"\s*\{.*?each\.value\.role.*?\n\}`).MatchString(main) {
		t.Errorf("role attachment should read each.value.role:\n%s", main)
	}
	if !regexp.MustCompile(`(?s)"aws_iam_user_policy_attachment"\s+"policy"\s*\{.*?each\.value\.user.*?\n\}`).MatchString(main) {
		t.Errorf("user attachment should read each.value.user:\n%s", main)
	}

	if _, d := hclparse.NewParser().ParseHCL([]byte(main), "main.tf"); d.HasErrors() {
		t.Errorf("main.tf does not parse: %s", d)
	}
	if _, d := hclparse.NewParser().ParseHCL([]byte(locals), "locals.tf"); d.HasErrors() {
		t.Errorf("locals.tf does not parse: %s", d)
	}
}

// A name-suffix match ("_id"/"_arn") alone isn't enough to know an
// attribute is really a foreign AWS resource reference. Confirmed against
// a real account: aws_cloudwatch_event_target's target_id is a free-text
// label ("AuditManagerTarget"), not an opaque id -- the suffix alone sent
// it through hoistExternalRefs as a required, no-default root variable,
// the same treatment a genuine foreign vpc_id gets, forcing every
// consumer to explicitly re-supply an arbitrary label at the root for no
// reason. A value that doesn't look like a real AWS id/ARN should get the
// ordinary defaulted treatment instead, same as "name"; a value that DOES
// look external must still go through the root-required path unchanged.
func TestHoistPlainLabelVsRealExternalID(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_cloudwatch_event_rule", Region: "us-east-1", ID: "r1",
				Config: map[string]any{"name": "r1", "event_pattern": "{}"}},
			{TFType: "aws_cloudwatch_event_target", Region: "us-east-1", ID: "t1",
				Config: map[string]any{
					"rule":      "r1",
					"arn":       "arn:aws:lambda:us-east-1:123456789012:function:f",
					"target_id": "AuditManagerTarget", // a free-text label, not an AWS id
				}},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-1",
				Config: map[string]any{"name": "web", "vpc_id": "vpc-ba627dde"}}, // a REAL foreign id
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	// target_id: hoisted with its discovered value as the default, no root wiring needed.
	integVars := read(t, dir, "modules", "integration", "variables.tf")
	if !regexp.MustCompile(`variable "\w*target_id"\s*\{[^}]*default\s*=\s*"AuditManagerTarget"`).MatchString(integVars) {
		t.Errorf("target_id (a plain label) should hoist with a default, got:\n%s", integVars)
	}
	rootMain := read(t, dir, "main.tf")
	if strings.Contains(rootMain, "AuditManagerTarget") {
		t.Errorf("a defaulted label should never need explicit root wiring, got:\n%s", rootMain)
	}

	// vpc_id: still a required, no-default root variable -- unchanged.
	netVars := read(t, dir, "modules", "network", "variables.tf")
	if !strings.Contains(netVars, `variable "vpc_id"`) {
		t.Fatalf("expected the required \"vpc_id\" variable, got:\n%s", netVars)
	}
	idx := strings.Index(netVars, `variable "vpc_id" {`)
	block := netVars[idx : idx+strings.Index(netVars[idx:], "}")]
	if strings.Contains(block, "default") {
		t.Errorf("a real foreign id must stay a required variable (no default), got:\n%s", block)
	}
	if !regexp.MustCompile(`vpc_id\s+= "vpc-ba627dde"`).MatchString(rootMain) {
		t.Errorf("root main.tf should still supply the real foreign vpc_id explicitly, got:\n%s", rootMain)
	}
}

// A resource's own "name" is an identity label, never a pointer into
// Terraform's graph -- even when its value happens to equal some other
// resource's bare id. Confirmed against a real account: an
// aws_security_group named "tailnet" collided with an aws_ecs_cluster
// whose id is also "tailnet" (an ordinary naming coincidence, no AWS-level
// cause), and the security group's own name got wired to
// var.compute_tailnet_id instead of staying the literal "tailnet". A
// second, independent case from the same class as the earlier Cloud Map
// namespace fix (typeNoRefKeys), confirming "name" needed the general
// fix, not another special case.
func TestNameNeverBecomesAReference(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_ecs_cluster", Region: "us-east-1", ID: "tailnet",
				ARN:    "arn:aws:ecs:us-east-1:123456789012:cluster/tailnet",
				Config: map[string]any{"name": "tailnet"}},
			// same category (compute) as the cluster -- a LEGITIMATE
			// same-category reference via a dedicated "cluster" attribute
			// must still wire correctly; only "name" is excluded.
			{TFType: "aws_ecs_service", Region: "us-east-1", ID: "tailnet/svc",
				ARN:    "arn:aws:ecs:us-east-1:123456789012:service/tailnet/svc",
				Config: map[string]any{"name": "svc", "cluster": "tailnet", "desired_count": float64(1)}},
			// different category (network) -- the coincidental collision:
			// this security group's OWN name happens to equal the
			// cluster's id, purely by naming coincidence.
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-0abc1234",
				ARN:    "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc1234",
				Config: map[string]any{"name": "tailnet", "description": "tailnet sg"}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}

	// both are sole of their type -> "main" per the naming convention;
	// the point here is the *reference*, not the block name.
	compute := read(t, dir, "modules", "compute", "main.tf")
	if !regexp.MustCompile(`cluster\s*=\s*aws_ecs_cluster\.main\.id`).MatchString(compute) {
		t.Errorf("legitimate same-category reference (service -> cluster) should still wire correctly:\n%s", compute)
	}

	// the security group's "name" is still hoisted (the ordinary, unrelated
	// hoistAttrs behavior -- ANY resource's "name" becomes var.<x>_name
	// with a default) but that default must be its own literal "tailnet",
	// never a cross-module reference to the cluster.
	netVars := read(t, dir, "modules", "network", "variables.tf")
	if !regexp.MustCompile(`variable "security_group_name"\s*\{[^}]*default\s*=\s*"tailnet"`).MatchString(netVars) {
		t.Errorf("security group name should hoist with its own literal default \"tailnet\":\n%s", netVars)
	}
	if strings.Contains(netVars, "compute") {
		t.Errorf("no cross-module (compute) wiring should exist for the security group's name at all:\n%s", netVars)
	}
	rootMain := read(t, dir, "main.tf")
	if strings.Contains(rootMain, "tailnet_id") || strings.Contains(rootMain, "compute.main") {
		t.Errorf("root main.tf should not wire the security group's name to the compute module:\n%s", rootMain)
	}
}

// aws_cloudfront_distribution.aliases (custom domain names) is a genuine
// per-deployment knob -- confirmed against a real account -- but hoist()
// was scalar-only, so it never got lifted into a variable at all.
func TestHoistListAttr(t *testing.T) {
	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_cloudfront_distribution", ID: "E1", ARN: "arn:aws:cloudfront::123456789012:distribution/E1",
				Config: map[string]any{
					"aliases": []any{"blog.example.com", "example.com"},
					"enabled": true,
				}},
		},
	}
	dir := t.TempDir()
	if _, err := Write(inv, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	main := read(t, dir, "modules", "edge", "main.tf")
	if !strings.Contains(main, "var.cloudfront_distribution_aliases") {
		t.Errorf("aliases should be hoisted, got:\n%s", main)
	}
	vars := read(t, dir, "modules", "edge", "variables.tf")
	if !strings.Contains(vars, `"blog.example.com"`) || !strings.Contains(vars, `"example.com"`) {
		t.Errorf("hoisted aliases variable should default to the discovered domain list, got:\n%s", vars)
	}
	if _, d := hclparse.NewParser().ParseHCL([]byte(vars), "variables.tf"); d.HasErrors() {
		t.Errorf("variables.tf does not parse: %s", d)
	}
}
