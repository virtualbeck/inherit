package emit

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/virtualbeck/inherit/internal/redact"
	"github.com/virtualbeck/inherit/model"
)

// TestWriteTofuValidate renders a spread of resource types and, when tofu or
// terraform is on PATH, actually runs `init -backend=false` + `validate` on the
// output. Skipped otherwise (CI has no provider mirror).
func TestWriteTofuValidate(t *testing.T) {
	if os.Getenv("INHERIT_INTEGRATION") == "" {
		t.Skip("set INHERIT_INTEGRATION=1 to run (needs tofu/terraform + provider download)")
	}
	bin := ""
	for _, b := range []string{"tofu", "terraform"} {
		if _, err := exec.LookPath(b); err == nil {
			bin = b
			break
		}
	}
	if bin == "" {
		t.Skip("no tofu/terraform on PATH")
	}

	inv := model.Inventory{
		Account: "123456789012", Regions: []string{"us-east-1"},
		Resources: []model.Resource{
			{TFType: "aws_vpc", Region: "us-east-1", ID: "vpc-1", Tags: map[string]string{"Name": "main"},
				Config: map[string]any{"cidr_block": "10.0.0.0/16", "instance_tenancy": "default", "tags": map[string]string{"Name": "main"}}},
			{TFType: "aws_subnet", Region: "us-east-1", ID: "subnet-1",
				Config: map[string]any{"vpc_id": "vpc-1", "cidr_block": "10.0.1.0/24", "availability_zone": "us-east-1a", "map_public_ip_on_launch": false}},
			{TFType: "aws_security_group", Region: "us-east-1", ID: "sg-1",
				Config: map[string]any{"name": "web", "description": "web", "vpc_id": "vpc-1"}},
			{TFType: "aws_wafv2_web_acl", Region: "us-east-1", ID: "webacl/acl/abc",
				Config: map[string]any{"name": "acl", "scope": "REGIONAL",
					"default_action":    map[string]any{"allow": map[string]any{}},
					"visibility_config": map[string]any{"cloudwatch_metrics_enabled": true, "metric_name": "acl", "sampled_requests_enabled": true},
					"rule_json":         `[{"Name":"r1","Priority":1,"Statement":{"GeoMatchStatement":{"CountryCodes":["US"]}},"Action":{"Block":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"r1"}}]`}},
			{TFType: "aws_route_table", Region: "us-east-1", ID: "rtb-1",
				Config: map[string]any{"vpc_id": "vpc-1", "route": []any{
					map[string]any{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"},
				}}},
			// mixes every ingress/egress shape hydrateNetworkACL produces:
			// no port range (protocol "-1"), a real TCP port range, an ICMP
			// type/code pair, and an IPv6-only rule -- from_port/to_port/
			// icmp_type/icmp_code are all Required within the object type
			// (a real number, not null, unlike cidr_block/ipv6_cidr_block
			// which accept null), so this catches a regression either way.
			{TFType: "aws_network_acl", Region: "us-east-1", ID: "acl-1",
				Config: map[string]any{"vpc_id": "vpc-1",
					"ingress": []any{
						map[string]any{"rule_no": float64(100), "action": "allow", "protocol": "-1",
							"cidr_block": "0.0.0.0/0", "from_port": int32(0), "to_port": int32(0), "icmp_type": int32(0), "icmp_code": int32(0)},
						map[string]any{"rule_no": float64(101), "action": "allow", "protocol": "6",
							"cidr_block": "10.0.0.0/8", "from_port": int32(443), "to_port": int32(443), "icmp_type": int32(0), "icmp_code": int32(0)},
						map[string]any{"rule_no": float64(102), "action": "allow", "protocol": "1",
							"cidr_block": "0.0.0.0/0", "from_port": int32(0), "to_port": int32(0), "icmp_type": int32(8), "icmp_code": int32(0)},
						map[string]any{"rule_no": float64(103), "action": "allow", "protocol": "-1",
							"ipv6_cidr_block": "::/0", "from_port": int32(0), "to_port": int32(0), "icmp_type": int32(0), "icmp_code": int32(0)},
					}}},
			// the retype-sentinel path (a VPC's default network ACL): a
			// different identifying attribute (default_network_acl_id, not
			// vpc_id -- vpc_id is computed-only here) and rules modeled as
			// real nested blocks rather than an object-typed collection, but
			// the same rule-building shape from hydrateNetworkACL works for
			// both since writeBlock dispatches on the schema, not the data.
			{TFType: "aws_default_network_acl", Region: "us-east-1", ID: "acl-default-1",
				Config: map[string]any{"default_network_acl_id": "acl-default-1",
					"ingress": []any{
						map[string]any{"rule_no": float64(100), "action": "allow", "protocol": "-1",
							"cidr_block": "0.0.0.0/0", "from_port": int32(0), "to_port": int32(0)},
					}}},
			// SecureString (placeholder value, never a real secret) and a
			// plain String (real recoverable value) -- the provider requires
			// exactly one of value/insecure_value/value_wo on every
			// aws_ssm_parameter regardless of type.
			{TFType: "aws_ssm_parameter", Region: "us-east-1", ID: "/app/db/password",
				Config: map[string]any{"name": "/app/db/password", "type": "SecureString", "value": "REPLACE_ME (inherit does not read SecureString values)"}},
			{TFType: "aws_ssm_parameter", Region: "us-east-1", ID: "/app/config",
				Config: map[string]any{"name": "/app/config", "type": "String", "value": "some-real-config-value"}},
			{TFType: "aws_cloudfront_vpc_origin", ID: "vo-1",
				Config: map[string]any{"vpc_origin_endpoint_config": map[string]any{
					"arn":  "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/1",
					"name": "vo-1", "http_port": float64(80), "https_port": float64(443),
					"origin_protocol_policy": "https-only",
					"origin_ssl_protocols":   map[string]any{"items": []any{"TLSv1.2"}, "quantity": float64(1)},
				}}},
			{TFType: "aws_dlm_lifecycle_policy", Region: "us-east-1", ID: "policy-1",
				Config: map[string]any{
					"description": "daily ebs snapshots", "execution_role_arn": "arn:aws:iam::123456789012:role/dlm",
					"state": "ENABLED",
					"policy_details": map[string]any{
						"resource_types": []any{"VOLUME"},
						"target_tags":    map[string]string{"Backup": "true"},
						"schedule": []any{
							map[string]any{"name": "daily", "create_rule": map[string]any{"interval": float64(24), "interval_unit": "HOURS"},
								"retain_rule": map[string]any{"count": float64(7)}},
						},
					}}},
			{TFType: "aws_ec2_network_insights_path", Region: "us-east-1", ID: "nip-1",
				Config: map[string]any{"source": "eni-1", "protocol": "tcp"}},
			{TFType: "aws_lambda_function", Region: "us-east-1", ID: "fn-1",
				Config: map[string]any{"function_name": "fn-1", "role": "arn:aws:iam::123456789012:role/r1",
					"handler": "index.handler", "runtime": "python3.12"}},
			// Redacted values (internal/redact) must still validate: each
			// lands under ignore_changes, whole-value placeholders in
			// format-checked attributes (base64) are left out of config.
			{TFType: "aws_lambda_function", Region: "us-east-1", ID: "fn-redacted",
				Config: map[string]any{"function_name": "fn-redacted", "role": "arn:aws:iam::123456789012:role/r1",
					"handler": "index.handler", "runtime": "python3.12",
					"environment": []any{map[string]any{"variables": map[string]any{"DB_PASSWORD": redact.Sentinel}}}}},
			{TFType: "aws_ssm_parameter", Region: "us-east-1", ID: "/app/redacted",
				Config: map[string]any{"name": "/app/redacted", "type": "String", "value": redact.Sentinel}},
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-redacted",
				Config: map[string]any{"instance_type": "t3.micro", "ami": "ami-123", "user_data": redact.Sentinel}},
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-redacted-b64",
				Config: map[string]any{"instance_type": "t3.micro", "ami": "ami-123", "user_data_base64": redact.Sentinel}},
			{TFType: "aws_launch_template", Region: "us-east-1", ID: "lt-redacted",
				Config: map[string]any{"name": "lt-redacted", "user_data": redact.Sentinel}},
			{TFType: "aws_iam_user", ID: "u-redacted",
				Config: map[string]any{"name": "u-redacted", "tags": map[string]string{redact.Sentinel + "_key_1": "ci deploy key"}}},
			{TFType: "aws_ssm_association", Region: "us-east-1", ID: "a-1",
				Config: map[string]any{"name": "AWS-GatherSoftwareInventory",
					"parameters": map[string]any{"applications": "Enabled", "awsComponents": "Enabled"}}},
			{TFType: "aws_api_gateway_rest_api", Region: "us-east-1", ID: "rest-1",
				Config: map[string]any{"name": "api"}},
			{TFType: "aws_api_gateway_resource", Region: "us-east-1", ID: "res-1", ImportID: "rest-1/res-1",
				Config: map[string]any{"rest_api_id": "rest-1", "parent_id": "root-1", "path_part": "widgets"}},
			{TFType: "aws_api_gateway_method", Region: "us-east-1", ID: "rest-1/res-1/GET", ImportID: "rest-1/res-1/GET",
				Config: map[string]any{"rest_api_id": "rest-1", "resource_id": "res-1", "http_method": "GET", "authorization": "NONE"}},
			{TFType: "aws_api_gateway_integration", Region: "us-east-1", ID: "rest-1/res-1/GET", ImportID: "rest-1/res-1/GET",
				Config: map[string]any{"rest_api_id": "rest-1", "resource_id": "res-1", "http_method": "GET", "type": "MOCK",
					"request_templates": map[string]any{"application/json": "{\"statusCode\":200}"}}},
			{TFType: "aws_appautoscaling_target", Region: "us-east-1", ID: "ecs/service/c/s/ecs:service:DesiredCount",
				ImportID: "ecs/service/c/s/ecs:service:DesiredCount",
				Config: map[string]any{"service_namespace": "ecs", "resource_id": "service/c/s",
					"scalable_dimension": "ecs:service:DesiredCount", "min_capacity": 1, "max_capacity": 4,
					"tags": map[string]string{"Team": "platform"}}},
			{TFType: "aws_appautoscaling_policy", Region: "us-east-1", ID: "ecs/service/c/s/ecs:service:DesiredCount/cpu",
				ImportID: "ecs/service/c/s/ecs:service:DesiredCount/cpu",
				Config: map[string]any{"name": "cpu", "service_namespace": "ecs", "resource_id": "service/c/s",
					"scalable_dimension": "ecs:service:DesiredCount", "policy_type": "TargetTrackingScaling",
					"target_tracking_scaling_policy_configuration": map[string]any{"target_value": float64(60),
						"predefined_metric_specification": map[string]any{"predefined_metric_type": "ECSServiceAverageCPUUtilization"}}}},
			{TFType: "aws_vpc_security_group_ingress_rule", Region: "us-east-1", ID: "sgr-1",
				Config: map[string]any{"security_group_id": "sg-1", "ip_protocol": "tcp", "from_port": float64(443), "to_port": float64(443), "cidr_ipv4": "0.0.0.0/0"}},
			{TFType: "aws_cloudwatch_metric_alarm", Region: "us-east-1", ID: "cpu",
				Config: map[string]any{"alarm_name": "cpu", "comparison_operator": "GreaterThanThreshold", "evaluation_periods": float64(1),
					"metric_name": "CPUUtilization", "namespace": "AWS/EC2", "period": float64(300), "statistic": "Average", "threshold": float64(80),
					"dimensions": map[string]any{"InstanceId": "i-abc"},
					// forces cross-module wiring (observability -> integration), which
					// generates an input `variable` block: guards the type-constraint form
					"alarm_actions": []any{"arn:aws:sns:us-east-1:123456789012:alerts"}}},
			{TFType: "aws_sns_topic", Region: "us-east-1", ID: "arn:aws:sns:us-east-1:123456789012:alerts",
				ARN:    "arn:aws:sns:us-east-1:123456789012:alerts",
				Config: map[string]any{"name": "alerts"}},
			{TFType: "aws_iam_role", ID: "r1",
				Config: map[string]any{"name": "r1", "assume_role_policy": `{"Version":"2012-10-17","Statement":[]}`}},
			{TFType: "aws_sqs_queue", Region: "us-east-1", ID: "q1",
				Config: map[string]any{"name": "q1", "visibility_timeout_seconds": float64(30)}},
			{TFType: "aws_dynamodb_table", Region: "us-east-1", ID: "t1",
				Config: map[string]any{"name": "t1", "billing_mode": "PAY_PER_REQUEST", "hash_key": "pk",
					"attribute": []any{map[string]any{"name": "pk", "type": "S"}}}},
			{TFType: "aws_cloudfront_distribution", ID: "E123",
				Config: map[string]any{
					"enabled": true, "comment": "cdn",
					"origin": []any{map[string]any{
						"origin_id": "s3", "domain_name": "b.s3.amazonaws.com",
						"s3_origin_config": map[string]any{"origin_access_identity": ""},
					}},
					"default_cache_behavior": map[string]any{
						"target_origin_id": "s3", "viewer_protocol_policy": "redirect-to-https",
						"allowed_methods": []any{"GET", "HEAD"}, "cached_methods": []any{"GET", "HEAD"},
						"forwarded_values": map[string]any{"query_string": false, "cookies": map[string]any{"forward": "none"}},
					},
					"restrictions":       map[string]any{"geo_restriction": map[string]any{"restriction_type": "none"}},
					"viewer_certificate": map[string]any{"cloudfront_default_certificate": true},
				}},
			// a resource outside the default region: exercises the aliased
			// provider + module `providers = {...}` passthrough end to end.
			{TFType: "aws_vpc", Region: "us-west-2", ID: "vpc-2",
				Config: map[string]any{"cidr_block": "10.9.0.0/16"}},
			// same-region ARN literal on an aliased resource: must parameterize
			// through data.aws_region.us_west_2 (itself aliased), not .current
			// (which would resolve via the module's default us-east-1 provider
			// and corrupt the ARN's region segment).
			{TFType: "aws_kms_key", Region: "us-west-2", ID: "key-1",
				ARN:    "arn:aws:kms:us-west-2:123456789012:key/key-1",
				Config: map[string]any{"description": "test"}},
			{TFType: "aws_db_instance", Region: "us-west-2", ID: "db-2",
				Config: map[string]any{"identifier": "db-2", "engine": "postgres", "instance_class": "db.t3.micro",
					"allocated_storage": float64(20),
					"kms_key_id":        "arn:aws:kms:us-west-2:123456789012:key/key-1"}},
			{TFType: "aws_lb_listener_rule", Region: "us-east-1", ID: "rule-1",
				Config: map[string]any{
					"listener_arn": "arn:aws:elasticloadbalancing:us-east-1:1:listener/app/x/1/2",
					"priority":     "10",
					"condition": []any{
						map[string]any{"path_pattern": map[string]any{"values": []any{"/api/*"}}},
					},
					"action": []any{
						map[string]any{"type": "redirect", "redirect": map[string]any{
							"status_code": "HTTP_301", "protocol": "HTTPS", "port": "443",
						}},
					},
					"tags": map[string]string{"Team": "platform"},
				}},
			// deletion_protection / idle_timeout / http2 / drop_invalid_header_fields:
			// these live behind a separate DescribeLoadBalancerAttributes call the
			// hydrator didn't make at all before, so config always omitted them --
			// a real ALB with any of these non-default showed a spurious diff.
			{TFType: "aws_lb", Region: "us-east-1", ID: "app/lb-1/abc",
				ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/lb-1/abc",
				Config: map[string]any{
					"name": "lb-1", "internal": false, "load_balancer_type": "application",
					"subnets": []any{"subnet-1"}, "security_groups": []any{"sg-1"},
					"enable_deletion_protection": true, "idle_timeout": float64(60),
					"enable_http2": true, "drop_invalid_header_fields": true,
				}},
			// default_action now reuses lbActions/lbForward (aws_lb_rules.go) so a
			// listener with stickiness or multiple target groups gets its real
			// forward{ target_group / stickiness } block instead of the old
			// hand-rolled loop, which only ever emitted target_group_arn.
			{TFType: "aws_lb_listener", Region: "us-east-1", ID: "app/lb-1/abc/def",
				ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/lb-1/abc/def",
				Config: map[string]any{
					"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/lb-1/abc",
					"port":              float64(443), "protocol": "HTTPS",
					"default_action": []any{
						map[string]any{"type": "forward", "forward": map[string]any{
							"target_group": []any{
								map[string]any{"arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc", "weight": float64(1)},
							},
							"stickiness": map[string]any{"enabled": true, "duration": float64(300)},
						}},
					},
				}},
			{TFType: "aws_ecs_service", Region: "us-east-1", ID: "svc-1",
				Config: map[string]any{
					"name": "svc-1", "cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/c1",
					"task_definition": "arn:aws:ecs:us-east-1:123456789012:task-definition/td:1",
					"desired_count":   float64(2), "launch_type": "FARGATE",
					"health_check_grace_period_seconds": float64(120),
					"deployment_circuit_breaker":        map[string]any{"enable": true, "rollback": true},
					"load_balancer": []any{
						map[string]any{"container_name": "app", "container_port": float64(8080),
							"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc"},
					},
				}},
			// user_data isn't part of DescribeInstances -- a separate
			// DescribeInstanceAttribute call the hydrator didn't make at all.
			{TFType: "aws_instance", Region: "us-east-1", ID: "i-1",
				Config: map[string]any{
					"instance_type": "t3.micro", "ami": "ami-123",
					"user_data": "#!/bin/bash\necho hello\n",
				}},
			{TFType: "aws_db_option_group", Region: "us-east-1", ID: "og-1",
				Config: map[string]any{
					"name": "og-1", "engine_name": "oracle-se2", "major_engine_version": "19",
					"option_group_description": "test og",
					"option": []any{
						map[string]any{"option_name": "LOCATOR", "port": float64(0)},
					},
				}},
			{TFType: "aws_db_parameter_group", Region: "us-east-1", ID: "pg-1",
				Config: map[string]any{
					"name": "pg-1", "family": "postgres15",
					"parameter": []any{
						map[string]any{"name": "log_statement", "value": "all", "apply_method": "immediate"},
					},
				}},
			{TFType: "aws_route53_zone", ID: "Z123",
				Config: map[string]any{
					"name": "internal.example.com",
					"vpc": []any{
						map[string]any{"vpc_id": "vpc-1", "vpc_region": "us-east-1"},
					},
				}},
			// schema[] and email_configuration.from_email_address are the two
			// fields Generic()'s filterNested silently dropped on a real pool
			// (whole-block-drop-on-missing-Required-subattr, the same failure
			// mode already seen on aws_cloudfront_vpc_origin); rebuilt explicitly
			// now, along with software_token_mfa_configuration which has no
			// DescribeUserPool equivalent at all.
			{TFType: "aws_cognito_user_pool", Region: "us-east-1", ID: "pool-1",
				Config: map[string]any{
					"name":              "pool-1",
					"mfa_configuration": "OPTIONAL",
					"schema": []any{
						map[string]any{"name": "custom_field", "attribute_data_type": "String",
							"developer_only_attribute": false, "mutable": true, "required": false,
							"string_attribute_constraints": map[string]any{"min_length": "0", "max_length": "256"}},
					},
					"email_configuration": map[string]any{
						"email_sending_account": "DEVELOPER",
						"from_email_address":    "noreply@example.com",
						"source_arn":            "arn:aws:ses:us-east-1:123456789012:identity/example.com",
					},
					"software_token_mfa_configuration": map[string]any{"enabled": true},
				}},
			{TFType: "aws_cognito_user_pool_client", ID: "pool-1/client-1", ImportID: "pool-1/client-1",
				Config: map[string]any{
					"user_pool_id": "pool-1", "name": "client-1",
					"token_validity_units": map[string]any{
						"access_token": "minutes", "id_token": "minutes", "refresh_token": "days",
					},
				}},
			// tier-1 fanout additions: exercise the trickiest hand-built
			// nested shapes (finding_criteria's converted map->set-of-object,
			// condition/selection_tag, task_invocation_parameters' union,
			// object lock / intelligent tiering / ACL's owner+grant shape).
			{TFType: "aws_guardduty_filter", ID: "detector-1:my-filter", ImportID: "detector-1:my-filter",
				Config: map[string]any{
					"name": "my-filter", "detector_id": "detector-1", "action": "ARCHIVE", "rank": int32(1),
					"finding_criteria": []any{map[string]any{
						"criterion": []any{
							map[string]any{"field": "severity", "greater_than": "7"},
							map[string]any{"field": "region", "equals": []any{"us-east-1"}},
						},
					}},
				}},
			{TFType: "aws_backup_selection", ID: "sel-1", ImportID: "plan-1|sel-1",
				Config: map[string]any{
					"name": "sel-1", "plan_id": "plan-1", "iam_role_arn": "arn:aws:iam::123456789012:role/backup",
					"resources": []any{"arn:aws:dynamodb:us-east-1:123456789012:table/my-table"},
					"selection_tag": []any{
						map[string]any{"key": "backup", "type": "STRINGEQUALS", "value": "daily"},
					},
					"condition": []any{map[string]any{
						"string_equals": []any{map[string]any{"key": "aws:ResourceTag/env", "value": "prod"}},
					}},
				}},
			{TFType: "aws_ssm_maintenance_window_task", ID: "mw-1/task-1", ImportID: "mw-1/task-1",
				Config: map[string]any{
					"window_id": "mw-1", "task_arn": "AWS-RunShellScript", "task_type": "RUN_COMMAND", "priority": int32(1),
					"targets": []any{map[string]any{"key": "WindowTargetIds", "values": []any{"target-1"}}},
					"task_invocation_parameters": []any{map[string]any{
						"run_command_parameters": []any{map[string]any{
							"comment": "run it",
							"parameter": []any{
								map[string]any{"name": "commands", "values": []any{"echo hello"}},
							},
						}},
					}},
				}},
			{TFType: "aws_ec2_transit_gateway_route", ID: "tgw-rtb-1_10.0.0.0/16", ImportID: "tgw-rtb-1_10.0.0.0/16",
				Config: map[string]any{
					"transit_gateway_route_table_id": "tgw-rtb-1", "destination_cidr_block": "10.0.0.0/16",
					"transit_gateway_attachment_id": "tgw-attach-1",
				}},
			{TFType: "aws_emr_cluster", ID: "j-1", Tags: map[string]string{"Name": "fleet-cluster"},
				Config: map[string]any{
					"name": "fleet-cluster", "release_label": "emr-6.15.0", "service_role": "EMR_DefaultRole",
					"applications": []any{"Spark"},
					"master_instance_fleet": []any{map[string]any{
						"target_on_demand_capacity": int32(1),
						"instance_type_configs": []any{map[string]any{
							"instance_type": "m5.xlarge", "weighted_capacity": int32(1),
						}},
					}},
					"core_instance_fleet": []any{map[string]any{
						"target_spot_capacity": int32(2),
						"instance_type_configs": []any{
							map[string]any{"instance_type": "m5.xlarge", "weighted_capacity": int32(1)},
							map[string]any{"instance_type": "m5.2xlarge", "weighted_capacity": int32(2)},
						},
						"launch_specifications": []any{map[string]any{
							"spot_specification": []any{map[string]any{
								"timeout_action": "SWITCH_TO_ON_DEMAND", "timeout_duration_minutes": int32(10),
								"allocation_strategy": "capacity-optimized",
							}},
						}},
					}},
				}},
			{TFType: "aws_config_configuration_recorder", ID: "default", ImportID: "default",
				Config: map[string]any{
					"role_arn": "arn:aws:iam::123456789012:role/config-role",
					"recording_group": []any{map[string]any{
						"all_supported": true, "include_global_resource_types": true,
					}},
					"recording_mode": []any{map[string]any{"recording_frequency": "CONTINUOUS"}},
				}},
			{TFType: "aws_config_delivery_channel", ID: "default", ImportID: "default",
				Config: map[string]any{
					"s3_bucket_name":               "config-bucket",
					"snapshot_delivery_properties": []any{map[string]any{"delivery_frequency": "TwentyFour_Hours"}},
				}},
			{TFType: "aws_vpn_connection", ID: "vpn-1",
				Config: map[string]any{
					"type": "ipsec.1", "customer_gateway_id": "cgw-1", "vpn_gateway_id": "vgw-1",
					"static_routes_only":              false,
					"tunnel1_preshared_key":           "firstkey",
					"tunnel1_dpd_timeout_action":      "restart",
					"tunnel1_ike_versions":            []any{"ikev1", "ikev2"},
					"tunnel1_phase1_dh_group_numbers": []any{int32(14)},
					"tunnel2_preshared_key":           "secondkey",
					"tunnel2_dpd_timeout_action":      "clear",
				}},
			{TFType: "aws_efs_file_system", Region: "us-east-1", ID: "fs-1",
				Config: map[string]any{
					"creation_token": "fs-1",
					"protection":     []any{map[string]any{"replication_overwrite": "DISABLED"}},
				}},
			{TFType: "aws_eks_addon", Region: "us-east-1", ID: "cluster-1:vpc-cni",
				Config: map[string]any{
					"cluster_name": "cluster-1", "addon_name": "vpc-cni",
					"pod_identity_association": []any{
						map[string]any{"service_account": "vpc-cni-sa", "role_arn": "arn:aws:iam::123456789012:role/vpc-cni"},
					},
				}},
			{TFType: "aws_ecs_capacity_provider", Region: "us-east-1", ID: "cp-1",
				Config: map[string]any{
					"name": "cp-1",
					"managed_instances_provider": []any{map[string]any{
						"infrastructure_role_arn": "arn:aws:iam::123456789012:role/infra",
						"propagate_tags":          "CAPACITY_PROVIDER",
						"instance_launch_template": []any{map[string]any{
							"ec2_instance_profile_arn": "arn:aws:iam::123456789012:instance-profile/x",
							"network_configuration": []any{map[string]any{
								"subnets": []any{"subnet-1", "subnet-2"}, "security_groups": []any{"sg-1"},
							}},
							"instance_requirements": []any{map[string]any{
								"vcpu_count": []any{map[string]any{"min": int32(2), "max": int32(4)}},
								"memory_mib": []any{map[string]any{"min": int32(2048)}},
							}},
						}},
					}},
				}},
			{TFType: "aws_dms_endpoint", Region: "us-east-1", ID: "endpoint-1",
				Config: map[string]any{
					"endpoint_id": "endpoint-1", "endpoint_type": "source", "engine_name": "postgres",
					"server_name": "db.example.com", "port": int32(5432), "username": "dms",
					"database_name":     "app",
					"postgres_settings": []any{map[string]any{"slot_name": "dms_slot", "capture_ddls": true}},
				}},
			{TFType: "aws_mwaa_environment", Region: "us-east-1", ID: "env-1",
				Config: map[string]any{
					"name": "env-1", "execution_role_arn": "arn:aws:iam::123456789012:role/mwaa",
					"source_bucket_arn": "arn:aws:s3:::bucket", "dag_s3_path": "dags/",
					"max_workers": int32(10), "schedulers": int32(2),
					"kms_key": "arn:aws:kms:us-east-1:123456789012:key/x",
					"network_configuration": []any{map[string]any{
						"security_group_ids": []any{"sg-1"}, "subnet_ids": []any{"subnet-1", "subnet-2"},
					}},
				}},
			{TFType: "aws_default_vpc", Region: "us-east-1", ID: "vpc-default1",
				Config: map[string]any{
					"enable_dns_support": true, "enable_dns_hostnames": true,
					"enable_network_address_usage_metrics": false,
				}},
			{TFType: "aws_s3_bucket_object_lock_configuration", ID: "bucket-1",
				Config: map[string]any{
					"bucket": "bucket-1", "object_lock_enabled": "Enabled",
					"rule": []any{map[string]any{
						"default_retention": []any{map[string]any{"mode": "GOVERNANCE", "days": int32(30)}},
					}},
				}},
			{TFType: "aws_s3_bucket_intelligent_tiering_configuration", ID: "bucket-1:archive",
				Config: map[string]any{
					"bucket": "bucket-1", "name": "archive", "status": "Enabled",
					"filter":  map[string]any{"prefix": "logs/", "tags": map[string]string{"team": "platform"}},
					"tiering": []any{map[string]any{"access_tier": "ARCHIVE_ACCESS", "days": int32(90)}},
				}},
			{TFType: "aws_s3_bucket_acl", ID: "bucket-1",
				Config: map[string]any{
					"bucket": "bucket-1",
					"access_control_policy": []any{map[string]any{
						"owner": []any{map[string]any{"id": "owner-id"}},
						"grant": []any{map[string]any{
							"permission": "FULL_CONTROL",
							"grantee":    []any{map[string]any{"type": "CanonicalUser", "id": "owner-id"}},
						}},
					}},
				}},
			{TFType: "aws_lb_listener_certificate", ID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/x/x_arn:aws:acm:us-east-1:123456789012:certificate/x",
				Config: map[string]any{
					"listener_arn":    "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/x/x",
					"certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
				}},
			{TFType: "aws_dynamodb_table_replica", ID: "my-table:us-west-2", ImportID: "my-table:us-west-2",
				Config: map[string]any{"global_table_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/my-table"}},
			{TFType: "aws_msk_scram_secret_association", ID: "arn:aws:kafka:us-east-1:123456789012:cluster/x/x", ImportID: "arn:aws:kafka:us-east-1:123456789012:cluster/x/x",
				Config: map[string]any{
					"cluster_arn":     "arn:aws:kafka:us-east-1:123456789012:cluster/x/x",
					"secret_arn_list": []any{"arn:aws:secretsmanager:us-east-1:123456789012:secret:x"},
				}},
			{TFType: "aws_route53_resolver_rule_association", ID: "rslvr-rrassoc-1", ImportID: "rslvr-rrassoc-1",
				Config: map[string]any{"resolver_rule_id": "rslvr-rr-1", "vpc_id": "vpc-1"}},
			{TFType: "aws_ec2_transit_gateway_route_table_association", ID: "tgw-rtb-1_tgw-attach-1", ImportID: "tgw-rtb-1_tgw-attach-1",
				Config: map[string]any{"transit_gateway_route_table_id": "tgw-rtb-1", "transit_gateway_attachment_id": "tgw-attach-1"}},
			{TFType: "aws_ec2_transit_gateway_route_table_propagation", ID: "tgw-rtb-1_tgw-attach-2", ImportID: "tgw-rtb-1_tgw-attach-2",
				Config: map[string]any{"transit_gateway_route_table_id": "tgw-rtb-1", "transit_gateway_attachment_id": "tgw-attach-2"}},
			{TFType: "aws_ssm_maintenance_window_target", ID: "mw-1/target-1", ImportID: "mw-1/target-1",
				Config: map[string]any{
					"window_id": "mw-1", "resource_type": "INSTANCE",
					"targets": []any{map[string]any{"key": "tag:Env", "values": []any{"prod"}}},
				}},
			{TFType: "aws_guardduty_publishing_destination", ID: "detector-1:dest-1", ImportID: "detector-1:dest-1",
				Config: map[string]any{
					"detector_id": "detector-1", "destination_type": "S3",
					"kms_key_arn":     "arn:aws:kms:us-east-1:123456789012:key/x",
					"destination_arn": "arn:aws:s3:::my-bucket",
				}},
			{TFType: "aws_appconfig_environment", ID: "app-1/env-1", ImportID: "app-1/env-1",
				Config: map[string]any{
					"application_id": "app-1", "name": "prod",
					"monitor": []any{map[string]any{"alarm_arn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:x"}},
				}},
			{TFType: "aws_appconfig_configuration_profile", ID: "app-1/prof-1", ImportID: "app-1/prof-1",
				Config: map[string]any{
					"application_id": "app-1", "name": "prof", "location_uri": "hosted",
					"validator": []any{map[string]any{"type": "JSON_SCHEMA", "content": "{}"}},
				}},
			{TFType: "aws_appconfig_deployment_strategy", ID: "ds-1", ImportID: "ds-1",
				Config: map[string]any{
					"name": "deploy-fast", "deployment_duration_in_minutes": int32(20),
					"final_bake_time_in_minutes": int32(10), "growth_factor": float64(10),
					"growth_type": "LINEAR", "replicate_to": "NONE",
				}},
			// exercises actions/notification_property/event_batching_condition/
			// predicate+conditions all through Generic() at once.
			{TFType: "aws_glue_trigger", ID: "trig-1", ImportID: "trig-1",
				Config: map[string]any{
					"name": "trig-1", "type": "CONDITIONAL", "enabled": true,
					"actions": []any{
						map[string]any{"job_name": "job-1", "arguments": map[string]string{"--x": "y"},
							"notification_property": []any{map[string]any{"notify_delay_after": int32(5)}}},
					},
					"predicate": []any{map[string]any{
						"logical": "AND",
						"conditions": []any{
							map[string]any{"job_name": "job-1", "state": "SUCCEEDED", "logical_operator": "EQUALS"},
						},
					}},
					"event_batching_condition": []any{map[string]any{"batch_size": int32(10), "batch_window": int32(900)}},
				}},
			{TFType: "aws_glue_connection", ID: "conn-1", ImportID: "conn-1",
				Config: map[string]any{
					"name": "conn-1", "connection_type": "JDBC",
					"connection_properties": map[string]string{"JDBC_CONNECTION_URL": "jdbc:mysql://x/y", "USERNAME": "u", "PASSWORD": "****"},
				}},
			{TFType: "aws_glue_workflow", ID: "wf-1", ImportID: "wf-1",
				Config: map[string]any{
					"name": "wf-1", "max_concurrent_runs": int32(3),
					"default_run_properties": map[string]string{"stage": "prod"},
				}},
			{TFType: "aws_msk_configuration", ID: "cfg-1", ImportID: "cfg-1",
				Config: map[string]any{
					"name": "cfg-1", "server_properties": "auto.create.topics.enable=true",
					"kafka_versions": []any{"3.5.1"},
				}},
			// no arn/tags support at all -- reference_name is create-only
			// (never read back), so an empty block is the correct, real shape.
			{TFType: "aws_route53_delegation_set", ID: "N1PA6795SAMPLE", ImportID: "N1PA6795SAMPLE",
				Config: map[string]any{}},
			{TFType: "aws_sfn_activity", ID: "act-1", ImportID: "act-1",
				Config: map[string]any{
					"name": "act-1",
					"encryption_configuration": []any{map[string]any{
						"type": "AWS_OWNED_KEY",
					}},
				}},
			{TFType: "aws_dynamodb_kinesis_streaming_destination", ID: "tbl-1,arn:aws:kinesis:us-east-1:123456789012:stream/s1", ImportID: "tbl-1,arn:aws:kinesis:us-east-1:123456789012:stream/s1",
				Config: map[string]any{
					"table_name": "tbl-1", "stream_arn": "arn:aws:kinesis:us-east-1:123456789012:stream/s1",
					"approximate_creation_date_time_precision": "MILLISECOND",
				}},
			{TFType: "aws_dynamodb_contributor_insights", ID: "name:tbl-1/index:/123456789012", ImportID: "name:tbl-1/index:/123456789012",
				Config: map[string]any{"table_name": "tbl-1", "mode": "ACCESSED_AND_THROTTLED_KEYS"}},
			{TFType: "aws_ecr_registry_policy", ID: "123456789012", ImportID: "123456789012",
				Config: map[string]any{"policy": `{"Version":"2012-10-17","Statement":[{"Sid":"x","Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:ReplicateImage","Resource":"*"}]}`}},
			{TFType: "aws_ecr_replication_configuration", ID: "123456789012", ImportID: "123456789012",
				Config: map[string]any{
					"replication_configuration": []any{map[string]any{
						"rule": []any{map[string]any{
							"destination": []any{map[string]any{"region": "us-west-2", "registry_id": "123456789012"}},
							"repository_filter": []any{map[string]any{
								"filter": "prod-", "filter_type": "PREFIX_MATCH",
							}},
						}},
					}},
				}},
			{TFType: "aws_ecr_pull_through_cache_rule", ID: "docker-hub", ImportID: "docker-hub",
				Config: map[string]any{
					"ecr_repository_prefix": "docker-hub", "upstream_registry_url": "registry-1.docker.io",
				}},
			{TFType: "aws_backup_vault_policy", ID: "vault-1", ImportID: "vault-1",
				Config: map[string]any{
					"backup_vault_name": "vault-1",
					"policy":            `{"Version":"2012-10-17","Statement":[{"Sid":"x","Effect":"Allow","Principal":{"AWS":"*"},"Action":"backup:CopyIntoBackupVault","Resource":"*"}]}`,
				}},
			{TFType: "aws_backup_vault_notifications", ID: "vault-1", ImportID: "vault-1",
				Config: map[string]any{
					"backup_vault_name": "vault-1", "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:topic-1",
					"backup_vault_events": []any{"BACKUP_JOB_COMPLETED", "RESTORE_JOB_FAILED"},
				}},
			{TFType: "aws_backup_region_settings", ID: "us-east-1", ImportID: "us-east-1",
				Config: map[string]any{
					"resource_type_opt_in_preference":     map[string]any{"DynamoDB": true, "EFS": true},
					"resource_type_management_preference": map[string]any{"DynamoDB": true},
				}},
			{TFType: "aws_config_configuration_aggregator", ID: "agg-1", ImportID: "agg-1",
				Config: map[string]any{
					"name": "agg-1",
					"account_aggregation_source": []any{map[string]any{
						"account_ids": []any{"123456789012"}, "all_regions": true,
					}},
				}},
			{TFType: "aws_ssm_resource_data_sync", ID: "sync-1", ImportID: "sync-1",
				Config: map[string]any{
					"name": "sync-1",
					"s3_destination": []any{map[string]any{
						"bucket_name": "my-bucket", "region": "us-east-1", "sync_format": "JsonSerDe",
						"prefix": "ssm/", "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/x",
					}},
				}},
			{TFType: "aws_ssm_service_setting", ID: "/ssm/parameter-store/high-throughput-enabled", ImportID: "/ssm/parameter-store/high-throughput-enabled",
				Config: map[string]any{
					"setting_id": "/ssm/parameter-store/high-throughput-enabled", "setting_value": "true",
				}},
			{TFType: "aws_service_discovery_private_dns_namespace", ID: "ns-priv-1", ImportID: "ns-priv-1",
				Config: map[string]any{"name": "internal.local", "vpc": "vpc-1"}},
			{TFType: "aws_service_discovery_public_dns_namespace", ID: "ns-pub-1", ImportID: "ns-pub-1",
				Config: map[string]any{"name": "public.example.com"}},
			{TFType: "aws_service_discovery_http_namespace", ID: "ns-http-1", ImportID: "ns-http-1",
				Config: map[string]any{"name": "http-ns"}},
			{TFType: "aws_signer_signing_profile", ID: "prof-1", ImportID: "prof-1",
				Config: map[string]any{
					"name": "prof-1", "platform_id": "AWSLambda-SHA384-ECDSA",
					"signature_validity_period": []any{map[string]any{"value": int32(5), "type": "YEARS"}},
					"signing_material":          []any{map[string]any{"certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/x"}},
				}},
			{TFType: "aws_pipes_pipe", ID: "pipe-1", ImportID: "pipe-1",
				Config: map[string]any{
					"name":          "pipe-1",
					"role_arn":      "arn:aws:iam::123456789012:role/pipe-role",
					"source":        "arn:aws:dynamodb:us-east-1:123456789012:table/tbl/stream/2024-01-01T00:00:00.000",
					"target":        "arn:aws:sqs:us-east-1:123456789012:queue-1",
					"desired_state": "RUNNING",
					"source_parameters": []any{map[string]any{
						"dynamodb_stream_parameters": []any{map[string]any{
							"starting_position": "LATEST", "batch_size": int32(10),
						}},
						"filter_criteria": []any{map[string]any{
							"filter": []any{map[string]any{"pattern": `{"eventName":["INSERT"]}`}},
						}},
					}},
					"target_parameters": []any{map[string]any{
						"sqs_queue_parameters": []any{map[string]any{"message_group_id": "g1"}},
					}},
					"log_configuration": []any{map[string]any{
						"level": "ERROR",
						"cloudwatch_logs_log_destination": []any{map[string]any{
							"log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:pipe-logs",
						}},
					}},
				}},
			{TFType: "aws_ses_receipt_rule_set", ID: "rules-1", ImportID: "rules-1",
				Config: map[string]any{"rule_set_name": "rules-1"}},
			{TFType: "aws_sesv2_email_identity_policy", ID: "example.com|allow-1", ImportID: "example.com|allow-1",
				Config: map[string]any{
					"email_identity": "example.com", "policy_name": "allow-1",
					"policy": `{"Version":"2012-10-17","Statement":[{"Sid":"x","Effect":"Allow","Principal":{"AWS":"*"},"Action":"ses:SendEmail","Resource":"*"}]}`,
				}},
			{TFType: "aws_wafv2_web_acl_logging_configuration", ID: "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl/abc", ImportID: "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl/abc",
				Config: map[string]any{
					"resource_arn":            "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl/abc",
					"log_destination_configs": []any{"arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-x"},
					"logging_filter": []any{map[string]any{
						"default_behavior": "KEEP",
						"filter": []any{map[string]any{
							"behavior": "DROP", "requirement": "MEETS_ALL",
							"condition": []any{map[string]any{
								"action_condition": []any{map[string]any{"action": "COUNT"}},
							}},
						}},
					}},
				}},
			{TFType: "aws_vpc_endpoint_service", ID: "vpce-svc-1", ImportID: "vpce-svc-1",
				Config: map[string]any{
					"acceptance_required":        false,
					"network_load_balancer_arns": []any{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/x/1"},
					"allowed_principals":         []any{"arn:aws:iam::123456789012:root"},
					"supported_regions":          []any{"us-east-1", "us-west-2"},
				}},
			{TFType: "aws_route53_query_log", ID: "qlc-1", ImportID: "qlc-1",
				Config: map[string]any{
					"zone_id": "Z1D633PJN98FT9", "cloudwatch_log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/x",
				}},
			{TFType: "aws_cloudtrail_event_data_store", ID: "eds-1", ImportID: "eds-1",
				Config: map[string]any{
					"name": "eds-1", "multi_region_enabled": true, "retention_period": int32(90),
					"advanced_event_selector": []any{map[string]any{
						"name": "mgmt-events",
						"field_selector": []any{map[string]any{
							"field": "eventCategory", "equals": []any{"Management"},
						}},
					}},
				}},
			{TFType: "aws_datasync_agent", ID: "agent-1", ImportID: "agent-1",
				Config: map[string]any{"name": "agent-1"}},
			{TFType: "aws_datasync_location_s3", ID: "loc-s3-1", ImportID: "loc-s3-1",
				Config: map[string]any{
					"s3_bucket_arn": "arn:aws:s3:::my-bucket", "subdirectory": "/",
					"s3_config": map[string]any{"bucket_access_role_arn": "arn:aws:iam::123456789012:role/dsrole"},
				}},
			{TFType: "aws_datasync_location_nfs", ID: "loc-nfs-1", ImportID: "loc-nfs-1",
				Config: map[string]any{
					"server_hostname": "nfs.example.com", "subdirectory": "/export",
					"on_prem_config": []any{map[string]any{"agent_arns": []any{"arn:aws:datasync:us-east-1:123456789012:agent/agent-1"}}},
				}},
			{TFType: "aws_datasync_location_efs", ID: "loc-efs-1", ImportID: "loc-efs-1",
				Config: map[string]any{
					"efs_file_system_arn": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-abcd1234",
					"subdirectory":        "/",
					"ec2_config": []any{map[string]any{
						"subnet_arn":          "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-1",
						"security_group_arns": []any{"arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"},
					}},
				}},
			{TFType: "aws_guardduty_detector_feature", ID: "detector-1/S3_DATA_EVENTS", ImportID: "detector-1/S3_DATA_EVENTS",
				Config: map[string]any{
					"detector_id": "detector-1", "name": "S3_DATA_EVENTS", "status": "ENABLED",
				}},
			{TFType: "aws_securityhub_account", ID: "123456789012", ImportID: "123456789012",
				Config: map[string]any{
					"auto_enable_controls": true, "control_finding_generator": "SECURITY_CONTROL",
				}},
			{TFType: "aws_securityhub_finding_aggregator", ID: "arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/x", ImportID: "arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/x",
				Config: map[string]any{
					"linking_mode": "ALL_REGIONS",
				}},
			{TFType: "aws_securityhub_standards_subscription", ID: "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0", ImportID: "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
				Config: map[string]any{
					"standards_arn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0",
				}},
			{TFType: "aws_ec2_transit_gateway_peering_attachment", ID: "tgw-attach-peer-1", ImportID: "tgw-attach-peer-1",
				Config: map[string]any{
					"transit_gateway_id": "tgw-1", "peer_transit_gateway_id": "tgw-2",
					"peer_account_id": "123456789012", "peer_region": "us-west-2",
					"options": []any{map[string]any{"dynamic_routing": "enable"}},
				}},
			{TFType: "aws_transfer_user", ID: "srv-1/bob", ImportID: "srv-1/bob",
				Config: map[string]any{
					"server_id": "srv-1", "user_name": "bob", "role": "arn:aws:iam::123456789012:role/transfer",
					"home_directory_type":     "LOGICAL",
					"home_directory_mappings": []any{map[string]any{"entry": "/", "target": "/bucket/home/bob"}},
					"posix_profile":           []any{map[string]any{"uid": int64(1000), "gid": int64(1000)}},
				}},
			{TFType: "aws_transfer_ssh_key", ID: "srv-1/bob/key-1", ImportID: "srv-1/bob/key-1",
				Config: map[string]any{
					"server_id": "srv-1", "user_name": "bob", "body": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test",
				}},
			{TFType: "aws_grafana_workspace", ID: "g-abc123", ImportID: "g-abc123",
				Config: map[string]any{
					"account_access_type": "CURRENT_ACCOUNT", "permission_type": "SERVICE_MANAGED",
					"authentication_providers": []any{"AWS_SSO"},
					"name":                     "my-grafana",
				}},
			{TFType: "aws_prometheus_workspace", ID: "ws-abc123", ImportID: "ws-abc123",
				Config: map[string]any{
					"alias": "my-amp",
					"logging_configuration": []any{map[string]any{
						"log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aps/x",
					}},
				}},
			{TFType: "aws_apprunner_vpc_connector", ID: "vc-1", ImportID: "vc-1",
				Config: map[string]any{
					"vpc_connector_name": "vc-1",
					"subnets":            []any{"subnet-1", "subnet-2"},
					"security_groups":    []any{"sg-1"},
				}},
			{TFType: "aws_apprunner_service", ID: "svc-1", ImportID: "svc-1",
				Config: map[string]any{
					"service_name": "svc-1",
					"source_configuration": map[string]any{
						"image_repository": map[string]any{
							"image_identifier":      "public.ecr.aws/x/y:latest",
							"image_repository_type": "ECR_PUBLIC",
						},
					},
					"instance_configuration": map[string]any{
						"cpu": "1024", "memory": "2048",
					},
					"health_check_configuration": map[string]any{
						"protocol": "HTTP", "path": "/health",
					},
				}},
			{TFType: "aws_dx_private_virtual_interface", ID: "dxvif-priv-1", ImportID: "dxvif-priv-1",
				Config: map[string]any{
					"connection_id": "dxcon-1", "name": "priv-vif", "vlan": int32(100),
					"address_family": "ipv4", "bgp_asn": int32(65000),
					"dx_gateway_id": "dx-gw-1",
				}},
			{TFType: "aws_dx_public_virtual_interface", ID: "dxvif-pub-1", ImportID: "dxvif-pub-1",
				Config: map[string]any{
					"connection_id": "dxcon-1", "name": "pub-vif", "vlan": int32(200),
					"address_family": "ipv4", "bgp_asn": int32(65001),
					"route_filter_prefixes": []any{"203.0.113.0/24"},
				}},
			{TFType: "aws_organizations_organizational_unit", ID: "ou-root-abcd1234", ImportID: "ou-root-abcd1234",
				Config: map[string]any{"name": "Engineering", "parent_id": "r-root1"}},
			{TFType: "aws_organizations_policy", ID: "p-abcd1234", ImportID: "p-abcd1234",
				Config: map[string]any{
					"name": "deny-region", "type": "SERVICE_CONTROL_POLICY",
					"content": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
				}},
			{TFType: "aws_organizations_account", ID: "123456789013", ImportID: "123456789013",
				Config: map[string]any{"name": "prod", "email": "prod@example.com", "parent_id": "r-root1"}},
			{TFType: "aws_sesv2_dedicated_ip_pool", ID: "pool-1", ImportID: "pool-1",
				Config: map[string]any{"pool_name": "pool-1", "scaling_mode": "STANDARD"}},
			{TFType: "aws_vpc_ipam", ID: "ipam-1", ImportID: "ipam-1",
				Config: map[string]any{
					"description": "primary ipam", "tier": "advanced",
					"operating_regions": []any{map[string]any{"region_name": "us-east-1"}},
				}},
			{TFType: "aws_ec2_client_vpn_endpoint", ID: "cvpn-endpoint-1", ImportID: "cvpn-endpoint-1",
				Config: map[string]any{
					"description": "vpn", "server_certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
					"client_cidr_block": "10.100.0.0/16", "vpc_id": "vpc-1",
					"authentication_options": []any{map[string]any{
						"type": "certificate-authentication", "root_certificate_chain_arn": "arn:aws:acm:us-east-1:123456789012:certificate/y",
					}},
					"connection_log_options": []any{map[string]any{"enabled": false}},
				}},
			{TFType: "aws_ebs_encryption_by_default", ID: "us-east-1", ImportID: "us-east-1",
				Config: map[string]any{"enabled": true}},
			{TFType: "aws_ebs_default_kms_key", ID: "us-east-1", ImportID: "us-east-1",
				Config: map[string]any{"key_arn": "arn:aws:kms:us-east-1:123456789012:key/abcd"}},
			{TFType: "aws_guardduty_ipset", ID: "d1:i1", ImportID: "d1:i1",
				Config: map[string]any{"detector_id": "d1", "activate": true, "format": "TXT", "location": "https://s3.amazonaws.com/bucket/ips.txt", "name": "ipset"}},
			{TFType: "aws_guardduty_threatintelset", ID: "d1:t1", ImportID: "d1:t1",
				Config: map[string]any{"detector_id": "d1", "activate": true, "format": "TXT", "location": "https://s3.amazonaws.com/bucket/threat.txt", "name": "threatset"}},
			{TFType: "aws_guardduty_member", ID: "d1:222222222222", ImportID: "d1:222222222222",
				Config: map[string]any{"detector_id": "d1", "account_id": "222222222222", "email": "member@example.com"}},
			{TFType: "aws_securityhub_action_target", ID: "arn:aws:securityhub:us-east-1:123456789012:action/custom/my-action", ImportID: "arn:aws:securityhub:us-east-1:123456789012:action/custom/my-action",
				Config: map[string]any{"identifier": "my-action", "name": "My Action", "description": "custom action"}},
			{TFType: "aws_securityhub_standards_control", ID: "arn:aws:securityhub:us-east-1:123456789012:control/cis-aws-foundations-benchmark/v/1.2.0/1.1", ImportID: "arn:aws:securityhub:us-east-1:123456789012:control/cis-aws-foundations-benchmark/v/1.2.0/1.1",
				Config: map[string]any{"standards_control_arn": "arn:aws:securityhub:us-east-1:123456789012:control/cis-aws-foundations-benchmark/v/1.2.0/1.1", "control_status": "ENABLED"}},
			{TFType: "aws_securityhub_organization_configuration", ID: "us-east-1", ImportID: "us-east-1",
				Config: map[string]any{"auto_enable": true, "auto_enable_standards": "DEFAULT"}},
			{TFType: "aws_securityhub_member", ID: "222222222222", ImportID: "222222222222",
				Config: map[string]any{"account_id": "222222222222", "email": "member@example.com"}},
			{TFType: "aws_cloudwatch_log_resource_policy", ID: "logs-policy", ImportID: "logs-policy",
				Config: map[string]any{"policy_name": "logs-policy", "policy_document": `{"Version":"2012-10-17","Statement":[]}`}},
			{TFType: "aws_cloudwatch_log_account_policy", ID: "acct-policy", ImportID: "acct-policy:DATA_PROTECTION_POLICY",
				Config: map[string]any{"policy_name": "acct-policy", "policy_type": "DATA_PROTECTION_POLICY", "policy_document": `{"Name":"policy","Version":"2021-06-01","Statement":[]}`}},
			{TFType: "aws_iam_account_password_policy", ID: "iam-account-password-policy", ImportID: "iam-account-password-policy",
				Config: map[string]any{"minimum_password_length": 14, "require_numbers": true, "require_symbols": true, "require_uppercase_characters": true, "require_lowercase_characters": true}},
			{TFType: "aws_iam_account_alias", ID: "my-account", ImportID: "my-account",
				Config: map[string]any{"account_alias": "my-account"}},
			{TFType: "aws_iam_access_key", ID: "AKIAEXAMPLE", ImportID: "AKIAEXAMPLE",
				Config: map[string]any{"user": "virtualbeck", "status": "Active"}},
			{TFType: "aws_iam_signing_certificate", ID: "CERTEXAMPLE:virtualbeck", ImportID: "CERTEXAMPLE:virtualbeck",
				Config: map[string]any{"user_name": "virtualbeck", "certificate_body": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n", "status": "Active"}},
			{TFType: "aws_iam_virtual_mfa_device", ID: "arn:aws:iam::123456789012:mfa/virtualbeck", ImportID: "arn:aws:iam::123456789012:mfa/virtualbeck",
				Config: map[string]any{"virtual_mfa_device_name": "virtualbeck"}},
			{TFType: "aws_route53_resolver_firewall_rule_group", ID: "rslvr-frg-1", ImportID: "rslvr-frg-1",
				Config: map[string]any{"name": "firewall-rules"}},
			{TFType: "aws_route53_resolver_firewall_domain_list", ID: "rslvr-fdl-1", ImportID: "rslvr-fdl-1",
				Config: map[string]any{"name": "blocklist", "domains": []any{"bad.example.com"}}},
			{TFType: "aws_route53_resolver_firewall_rule", ID: "rslvr-frg-1:rslvr-fdl-1", ImportID: "rslvr-frg-1:rslvr-fdl-1",
				Config: map[string]any{"name": "block-bad", "firewall_rule_group_id": "rslvr-frg-1", "firewall_domain_list_id": "rslvr-fdl-1", "priority": 100, "action": "BLOCK", "block_response": "NXDOMAIN"}},
			{TFType: "aws_route53_resolver_firewall_rule_group_association", ID: "rslvr-frgassoc-1", ImportID: "rslvr-frgassoc-1",
				Config: map[string]any{"name": "assoc", "firewall_rule_group_id": "rslvr-frg-1", "vpc_id": "vpc-1", "priority": 100}},
			{TFType: "aws_route53_resolver_query_log_config", ID: "rslvr-rqlc-1", ImportID: "rslvr-rqlc-1",
				Config: map[string]any{"name": "query-logs", "destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/resolver/logs"}},
			{TFType: "aws_route53_resolver_query_log_config_association", ID: "rslvr-rqlcassoc-1", ImportID: "rslvr-rqlcassoc-1",
				Config: map[string]any{"resolver_query_log_config_id": "rslvr-rqlc-1", "resource_id": "vpc-1"}},
			{TFType: "aws_lambda_code_signing_config", ID: "csc-1", ImportID: "csc-1",
				Config: map[string]any{
					"allowed_publishers": []any{map[string]any{"signing_profile_version_arns": []any{"arn:aws:signer:us-east-1:123456789012:/signing-profiles/x/1"}}},
					"policies":           []any{map[string]any{"untrusted_artifact_on_deployment": "Warn"}},
				}},
			{TFType: "aws_lambda_function_url", ID: "myfunc", ImportID: "myfunc",
				Config: map[string]any{"function_name": "myfunc", "authorization_type": "NONE"}},
			{TFType: "aws_lambda_function_event_invoke_config", ID: "myfunc", ImportID: "myfunc",
				Config: map[string]any{"function_name": "myfunc", "maximum_retry_attempts": 2}},
			{TFType: "aws_lambda_provisioned_concurrency_config", ID: "myfunc:1", ImportID: "myfunc:1",
				Config: map[string]any{"function_name": "myfunc", "qualifier": "1", "provisioned_concurrent_executions": 5}},
			{TFType: "aws_lambda_function_recursion_config", ID: "myfunc", ImportID: "myfunc",
				Config: map[string]any{"function_name": "myfunc", "recursive_loop": "Allow"}},
			{TFType: "aws_cloudfront_origin_access_control", ID: "oac-1", ImportID: "oac-1",
				Config: map[string]any{"name": "oac", "origin_access_control_origin_type": "s3", "signing_behavior": "always", "signing_protocol": "sigv4"}},
			{TFType: "aws_cloudfront_origin_access_identity", ID: "oai-1", ImportID: "oai-1",
				Config: map[string]any{"comment": "oai"}},
			{TFType: "aws_cloudfront_cache_policy", ID: "cp-1", ImportID: "cp-1",
				Config: map[string]any{
					"name": "cp", "min_ttl": 0, "default_ttl": 86400, "max_ttl": 31536000,
					"parameters_in_cache_key_and_forwarded_to_origin": []any{map[string]any{
						"cookies_config":                []any{map[string]any{"cookie_behavior": "none"}},
						"headers_config":                []any{map[string]any{"header_behavior": "none"}},
						"query_strings_config":          []any{map[string]any{"query_string_behavior": "none"}},
						"enable_accept_encoding_gzip":   true,
						"enable_accept_encoding_brotli": true,
					}},
				}},
			{TFType: "aws_cloudfront_origin_request_policy", ID: "orp-1", ImportID: "orp-1",
				Config: map[string]any{
					"name":                 "orp",
					"cookies_config":       []any{map[string]any{"cookie_behavior": "none"}},
					"headers_config":       []any{map[string]any{"header_behavior": "none"}},
					"query_strings_config": []any{map[string]any{"query_string_behavior": "none"}},
				}},
			{TFType: "aws_cloudfront_response_headers_policy", ID: "rhp-1", ImportID: "rhp-1",
				Config: map[string]any{"name": "rhp", "comment": "rhp",
					"security_headers_config": []any{map[string]any{
						"content_type_options": []any{map[string]any{"override": true}},
					}},
				}},
			{TFType: "aws_cloudfront_public_key", ID: "pk-1", ImportID: "pk-1",
				Config: map[string]any{"name": "pk", "encoded_key": "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"}},
			{TFType: "aws_cloudfront_key_group", ID: "kg-1", ImportID: "kg-1",
				Config: map[string]any{"name": "kg", "items": []any{"pk-1"}}},
			{TFType: "aws_cloudfront_function", ID: "myfn", ImportID: "myfn",
				Config: map[string]any{"name": "myfn", "runtime": "cloudfront-js-2.0", "code": "function handler(event) { return event.request; }"}},
			{TFType: "aws_api_gateway_api_key", ID: "apikey1", ImportID: "apikey1",
				Config: map[string]any{"name": "key1", "enabled": true}},
			{TFType: "aws_api_gateway_usage_plan", ID: "up-1", ImportID: "up-1",
				Config: map[string]any{
					"name":              "up1",
					"quota_settings":    []any{map[string]any{"limit": 1000, "offset": 0, "period": "MONTH"}},
					"throttle_settings": []any{map[string]any{"burst_limit": 5, "rate_limit": 10}},
					"api_stages": []any{map[string]any{
						"api_id": "restapi1", "stage": "prod",
						"throttle": []any{map[string]any{"path": "GET/resource", "burst_limit": 5, "rate_limit": 10}},
					}},
				}},
			{TFType: "aws_api_gateway_usage_plan_key", ID: "up-1/apikey1", ImportID: "up-1/apikey1",
				Config: map[string]any{"usage_plan_id": "up-1", "key_id": "apikey1", "key_type": "API_KEY"}},
			{TFType: "aws_api_gateway_domain_name", ID: "api.example.com", ImportID: "api.example.com",
				Config: map[string]any{
					"domain_name":              "api.example.com",
					"regional_certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
					"security_policy":          "TLS_1_2",
					"endpoint_configuration":   []any{map[string]any{"types": []any{"REGIONAL"}}},
				}},
			{TFType: "aws_api_gateway_base_path_mapping", ID: "api.example.com/", ImportID: "api.example.com/",
				Config: map[string]any{"domain_name": "api.example.com", "api_id": "restapi1", "stage_name": "prod"}},
			{TFType: "aws_api_gateway_vpc_link", ID: "vpclink1", ImportID: "vpclink1",
				Config: map[string]any{"name": "vpclink1", "target_arns": []any{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc"}}},
			{TFType: "aws_api_gateway_client_certificate", ID: "cert1", ImportID: "cert1",
				Config: map[string]any{"description": "client cert"}},
			{TFType: "aws_api_gateway_account", ID: "us-east-1", ImportID: "us-east-1",
				Config: map[string]any{}},
			{TFType: "aws_redshift_parameter_group", ID: "rpg-1", ImportID: "rpg-1",
				Config: map[string]any{"name": "rpg1", "family": "redshift-1.0",
					"parameter": []any{map[string]any{"name": "require_ssl", "value": "true"}}}},
			{TFType: "aws_redshift_subnet_group", ID: "rsg-1", ImportID: "rsg-1",
				Config: map[string]any{"name": "rsg1", "subnet_ids": []any{"subnet-1"}}},
			{TFType: "aws_redshift_event_subscription", ID: "res-1", ImportID: "res-1",
				Config: map[string]any{"name": "res1", "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:topic1", "enabled": true}},
			{TFType: "aws_neptune_cluster_parameter_group", ID: "npg-1", ImportID: "npg-1",
				Config: map[string]any{"name": "npg1", "family": "neptune1.3"}},
			{TFType: "aws_neptune_cluster_instance", ID: "neptune-instance-1", ImportID: "neptune-instance-1",
				Config: map[string]any{"identifier": "neptune-instance-1", "cluster_identifier": "neptune-cluster-1", "instance_class": "db.r5.large"}},
			{TFType: "aws_neptune_cluster_endpoint", ID: "neptune-cluster-1:custom-ep", ImportID: "neptune-cluster-1:custom-ep",
				Config: map[string]any{"cluster_endpoint_identifier": "custom-ep", "cluster_identifier": "neptune-cluster-1", "endpoint_type": "READER"}},
			{TFType: "aws_neptune_event_subscription", ID: "nes-1", ImportID: "nes-1",
				Config: map[string]any{"name": "nes1", "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:topic1", "enabled": true}},
			{TFType: "aws_vpc_ipam_scope", ID: "ipam-scope-1", ImportID: "ipam-scope-1",
				Config: map[string]any{"ipam_id": "ipam-1", "description": "custom scope"}},
			{TFType: "aws_vpc_ipam_pool", ID: "ipam-pool-1", ImportID: "ipam-pool-1",
				Config: map[string]any{"address_family": "ipv4", "ipam_scope_id": "ipam-scope-1", "locale": "us-east-1"}},
			{TFType: "aws_vpc_ipam_pool_cidr", ID: "10.0.0.0/16_ipam-pool-1", ImportID: "10.0.0.0/16_ipam-pool-1",
				Config: map[string]any{"ipam_pool_id": "ipam-pool-1", "cidr": "10.0.0.0/16"}},
			{TFType: "aws_vpc_ipam_resource_discovery", ID: "ipam-res-disco-1", ImportID: "ipam-res-disco-1",
				Config: map[string]any{"description": "discovery", "operating_regions": []any{map[string]any{"region_name": "us-east-1"}}}},
			{TFType: "aws_vpc_ipam_resource_discovery_association", ID: "ipam-res-disco-assoc-1", ImportID: "ipam-res-disco-assoc-1",
				Config: map[string]any{"ipam_id": "ipam-1", "ipam_resource_discovery_id": "ipam-res-disco-1"}},
			{TFType: "aws_cloudwatch_log_destination", ID: "dest1", ImportID: "dest1",
				Config: map[string]any{
					"name": "dest1", "role_arn": "arn:aws:iam::123456789012:role/CWLtoKinesisRole",
					"target_arn": "arn:aws:kinesis:us-east-1:123456789012:stream/dest-stream",
				}},
			{TFType: "aws_cloudwatch_log_destination_policy", ID: "dest1", ImportID: "dest1",
				Config: map[string]any{
					"destination_name": "dest1",
					"access_policy":    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"logs:PutSubscriptionFilter","Resource":"arn:aws:logs:us-east-1:123456789012:destination:dest1"}]}`,
				}},
			{TFType: "aws_config_retention_configuration", ID: "default", ImportID: "default",
				Config: map[string]any{"retention_period_in_days": 90}},
			{TFType: "aws_config_aggregate_authorization", ID: "222222222222:us-west-2", ImportID: "222222222222:us-west-2",
				Config: map[string]any{"account_id": "222222222222", "authorized_aws_region": "us-west-2"}},
			{TFType: "aws_opensearch_domain_policy", ID: "es-domain-1", ImportID: "es-domain-1",
				Config: map[string]any{
					"domain_name":     "es-domain-1",
					"access_policies": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*","Resource":"*"}]}`,
				}},
			{TFType: "aws_opensearch_vpc_endpoint", ID: "vpce-osdomain1", ImportID: "vpce-osdomain1",
				Config: map[string]any{
					"domain_arn":  "arn:aws:es:us-east-1:123456789012:domain/es-domain-1",
					"vpc_options": []any{map[string]any{"subnet_ids": []any{"subnet-1"}}},
				}},
			{TFType: "aws_route53_hosted_zone_dnssec", ID: "Z1234567890", ImportID: "Z1234567890",
				Config: map[string]any{"hosted_zone_id": "Z1234567890", "signing_status": "SIGNING"}},
			{TFType: "aws_route53_key_signing_key", ID: "Z1234567890,ksk1", ImportID: "Z1234567890,ksk1",
				Config: map[string]any{
					"hosted_zone_id":             "Z1234567890",
					"name":                       "ksk1",
					"key_management_service_arn": "arn:aws:kms:us-east-1:123456789012:key/abcd",
					"status":                     "ACTIVE",
				}},
			{TFType: "aws_route53_cidr_collection", ID: "cidr-col-1", ImportID: "cidr-col-1",
				Config: map[string]any{"name": "cidrcol1"}},
			{TFType: "aws_route53_cidr_location", ID: "cidr-col-1,office", ImportID: "cidr-col-1,office",
				Config: map[string]any{"cidr_collection_id": "cidr-col-1", "name": "office", "cidr_blocks": []any{"192.0.2.0/24"}}},
			{TFType: "aws_ec2_capacity_reservation", ID: "cr-1", ImportID: "cr-1",
				Config: map[string]any{"availability_zone": "us-east-1a", "instance_type": "m5.large", "instance_platform": "Linux/UNIX", "instance_count": 2}},
			{TFType: "aws_ec2_instance_connect_endpoint", ID: "eice-1", ImportID: "eice-1",
				Config: map[string]any{"subnet_id": "subnet-1"}},
			{TFType: "aws_ec2_carrier_gateway", ID: "cagw-1", ImportID: "cagw-1",
				Config: map[string]any{"vpc_id": "vpc-1"}},
			{TFType: "aws_ec2_host", ID: "h-1", ImportID: "h-1",
				Config: map[string]any{"availability_zone": "us-east-1a", "instance_type": "m5.large"}},
			{TFType: "aws_ec2_traffic_mirror_filter", ID: "tmf-1", ImportID: "tmf-1",
				Config: map[string]any{"description": "filter1", "network_services": []any{"amazon-dns"}}},
			{TFType: "aws_ec2_traffic_mirror_filter_rule", ID: "tmfr-1", ImportID: "tmfr-1",
				Config: map[string]any{
					"traffic_mirror_filter_id": "tmf-1", "destination_cidr_block": "10.0.0.0/16",
					"source_cidr_block": "0.0.0.0/0", "rule_action": "accept", "rule_number": 100, "traffic_direction": "ingress",
				}},
			{TFType: "aws_ec2_traffic_mirror_target", ID: "tmt-1", ImportID: "tmt-1",
				Config: map[string]any{"network_interface_id": "eni-1"}},
			{TFType: "aws_ec2_traffic_mirror_session", ID: "tms-1", ImportID: "tms-1",
				Config: map[string]any{
					"network_interface_id": "eni-2", "traffic_mirror_filter_id": "tmf-1",
					"traffic_mirror_target_id": "tmt-1", "session_number": 1,
				}},
			{TFType: "aws_guardduty_organization_admin_account", ID: "222222222222", ImportID: "222222222222",
				Config: map[string]any{"admin_account_id": "222222222222"}},
			{TFType: "aws_guardduty_organization_configuration", ID: "d1", ImportID: "d1",
				Config: map[string]any{"detector_id": "d1", "auto_enable_organization_members": "ALL"}},
			{TFType: "aws_guardduty_organization_configuration_feature", ID: "d1/S3_DATA_EVENTS", ImportID: "d1/S3_DATA_EVENTS",
				Config: map[string]any{"detector_id": "d1", "name": "S3_DATA_EVENTS", "auto_enable": "ALL"}},
			{TFType: "aws_guardduty_malware_protection_plan", ID: "mpp-1", ImportID: "mpp-1",
				Config: map[string]any{
					"role": "arn:aws:iam::123456789012:role/GuardDutyMalwareProtection",
					"protected_resource": []any{map[string]any{
						"s3_bucket": []any{map[string]any{"bucket_name": "scan-bucket"}},
					}},
				}},
			{TFType: "aws_transfer_profile", ID: "p-1", ImportID: "p-1",
				Config: map[string]any{"as2_id": "AS2ID", "profile_type": "LOCAL"}},
			{TFType: "aws_transfer_certificate", ID: "cert-1", ImportID: "cert-1",
				Config: map[string]any{"usage": "SIGNING", "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"}},
			{TFType: "aws_transfer_agreement", ID: "s-1/a-1", ImportID: "s-1/a-1",
				Config: map[string]any{
					"server_id": "s-1", "access_role": "arn:aws:iam::123456789012:role/TransferAccess",
					"base_directory": "/bucket/path", "local_profile_id": "p-1", "partner_profile_id": "p-2",
				}},
			{TFType: "aws_transfer_connector", ID: "c-1", ImportID: "c-1",
				Config: map[string]any{"access_role": "arn:aws:iam::123456789012:role/TransferConnector", "url": "https://partner.example.com/as2"}},
		},
	}

	dir := t.TempDir()
	res, err := Write(inv, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=x", "AWS_SECRET_ACCESS_KEY=x", "AWS_REGION=us-east-1")
		if out, err := cmd.CombinedOutput(); err != nil {
			var dump []byte
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
				if d != nil && !d.IsDir() && filepath.Ext(p) == ".tf" {
					b, _ := os.ReadFile(p)
					rel, _ := filepath.Rel(dir, p)
					dump = append(dump, []byte("\n--- "+rel+" ---\n")...)
					dump = append(dump, b...)
				}
				return nil
			})
			t.Fatalf("%s %v:\n%s\n%s", bin, args, out, dump)
		}
	}
	run("init", "-backend=false", "-input=false", "-no-color")
	run("validate", "-no-color")

	// --fast-import's override files, generated against this same real
	// (schema-driven, every resource type in the spread above) output, must
	// not break validation either -- and removing them must cleanly restore
	// the pre-override state.
	overridePaths, err := WriteImportOverrides(dir, res.Imports)
	if err != nil {
		t.Fatalf("WriteImportOverrides: %v", err)
	}
	if len(overridePaths) == 0 {
		t.Fatal("WriteImportOverrides wrote nothing for a spread with import specs")
	}
	run("validate", "-no-color")
	RemoveImportOverrides(overridePaths)
	for _, p := range overridePaths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("RemoveImportOverrides left %s behind", p)
		}
	}
	run("validate", "-no-color")
}
