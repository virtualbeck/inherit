package emit

import "regexp"

// First match wins.
var categoryRules = []struct {
	re  *regexp.Regexp
	cat string
}{
	{regexp.MustCompile(`^aws_(lb|alb|elb)(_|$)`), "loadbalancing"},
	{regexp.MustCompile(`^aws_(vpc|subnet|route_table|route$|internet_gateway|nat_gateway|eip|egress_only|network_acl|network_interface|vpc_endpoint|vpc_peering|vpc_dhcp|default_|customer_gateway|vpn_|dx_|ec2_transit|prefix_list)`), "network"},
	{regexp.MustCompile(`^aws_(security_group|vpc_security_group|default_security_group)`), "network"},
	{regexp.MustCompile(`^aws_(db_|rds_|elasticache_|dynamodb_|docdb|neptune|redshift|memorydb|timestream|qldb)`), "database"},
	{regexp.MustCompile(`^aws_(s3_|s3control_|efs_|fsx_|backup_|storagegateway_|glacier)`), "storage"},
	{regexp.MustCompile(`^aws_(iam_|kms_|secretsmanager_|acm_|acmpca_|wafv2_|waf_|fms_|shield_|guardduty|securityhub|inspector|macie|accessanalyzer)`), "security"},
	{regexp.MustCompile(`^aws_(cloudwatch_(?:metric_alarm|dashboard|composite|log_)|xray_|cloudtrail|oam_)`), "observability"},
	{regexp.MustCompile(`^aws_(sns_|sqs_|cloudwatch_event_|scheduler_|schemas_|pipes_|mq_|kinesis|firehose|msk_|mwaa_|sfn_|api_gateway|apigatewayv2|appsync)`), "integration"},
	{regexp.MustCompile(`^aws_(lambda_|instance$|ec2_|launch_template|autoscaling_|appautoscaling_|ecs_|ecr_|eks_|batch_|apprunner_|key_pair|ami$|placement_group|spot_)`), "compute"},
	{regexp.MustCompile(`^aws_route53_`), "dns"},
	{regexp.MustCompile(`^aws_cloudfront_`), "edge"},
}

func categoryFor(tfType string) string {
	for _, r := range categoryRules {
		if r.re.MatchString(tfType) {
			return r.cat
		}
	}
	return "other"
}
