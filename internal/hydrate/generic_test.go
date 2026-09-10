package hydrate

import (
	"testing"

	"github.com/virtualbeck/inherit-core/tfschema"
)

func TestGenericFiltersToSchema(t *testing.T) {
	sch, err := tfschema.Load()
	if err != nil {
		t.Fatal(err)
	}
	vpc, _ := sch.Resource("aws_vpc")

	// a marshalled-SDK-ish payload: real attrs, computed attrs, and junk
	sdk := map[string]any{
		"CidrBlock":       "10.0.0.0/16",
		"InstanceTenancy": "default",
		"VpcId":           "vpc-123", // computed identity -> dropped
		"OwnerId":         "1234",    // alwaysSkip -> dropped
		"IsDefault":       false,     // computed-only -> dropped
		"DhcpOptionsId":   "dopt-1",  // computed-only -> dropped
		"BogusField":      "x",       // unknown to schema -> dropped
	}
	got, err := Generic(sdk, vpc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["cidr_block"] != "10.0.0.0/16" || got["instance_tenancy"] != "default" {
		t.Fatalf("real attrs missing: %v", got)
	}
	for _, k := range []string{"vpc_id", "owner_id", "is_default", "bogus_field", "dhcp_options_id", "id", "arn"} {
		if _, present := got[k]; present {
			t.Errorf("%q should have been filtered out: %v", k, got)
		}
	}
}

// The SDK returns aws_lambda_function.environment as a single object, but the
// provider models it as list-nested; Generic must still keep the variables.
func TestGenericKeepsSingleObjectListBlock(t *testing.T) {
	sch, err := tfschema.Load()
	if err != nil {
		t.Fatal(err)
	}
	fn, _ := sch.Resource("aws_lambda_function")
	sdk := map[string]any{
		"FunctionName": "f",
		"Environment":  map[string]any{"Variables": map[string]any{"K": "v"}},
	}
	got, err := Generic(sdk, fn, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, ok := got["environment"].([]any)
	if !ok || len(env) != 1 {
		t.Fatalf("environment not kept as a 1-element list: %#v", got["environment"])
	}
	vars, _ := env[0].(map[string]any)["variables"].(map[string]any)
	if vars["K"] != "v" {
		t.Fatalf("environment variables lost: %#v", env[0])
	}
}

// A vpc_config the SDK returns with only optional fields set (non-VPC lambda)
// must be dropped, not emitted incomplete (subnet_ids/security_group_ids required).
func TestGenericDropsIncompleteRequiredBlock(t *testing.T) {
	sch, err := tfschema.Load()
	if err != nil {
		t.Fatal(err)
	}
	fn, _ := sch.Resource("aws_lambda_function")
	sdk := map[string]any{
		"FunctionName": "f",
		"VpcConfig":    map[string]any{"Ipv6AllowedForDualStack": false, "VpcId": ""},
	}
	got, err := Generic(sdk, fn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got["vpc_config"]; present {
		t.Fatalf("incomplete vpc_config should have been dropped: %#v", got["vpc_config"])
	}
}

func TestRegistryPopulated(t *testing.T) {
	for _, want := range []string{
		"aws_vpc", "aws_subnet", "aws_security_group", "aws_iam_role", "aws_iam_policy",
		"aws_iam_user", "aws_iam_group", "aws_iam_instance_profile",
		"aws_lambda_function", "aws_s3_bucket", "aws_sqs_queue", "aws_sns_topic",
		"aws_dynamodb_table", "aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm",
		"aws_cloudwatch_event_rule", "aws_kms_key", "aws_secretsmanager_secret",
		"aws_internet_gateway", "aws_nat_gateway", "aws_eip", "aws_route_table",
		"aws_db_instance", "aws_lb", "aws_lb_target_group", "aws_lb_listener",
		"aws_vpc_endpoint", "aws_network_acl", "aws_ecr_repository", "aws_acm_certificate",
		"aws_launch_template", "aws_autoscaling_group", "aws_route53_zone",
	} {
		if _, ok := registry[want]; !ok {
			t.Errorf("no hydrator registered for %s", want)
		}
	}
	// every hydrator target must exist in the arn map or be reachable
	for tf := range registry {
		if _, err := schemaFor(tf); err != nil {
			t.Errorf("%s: %v", tf, err)
		}
	}
}
