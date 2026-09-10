package hydrate

import "sort"

// extraCoveredTypes are Terraform resource types inherit emits without a direct
// registry hydrator: fanout children (produced from a parent) and gap-filled
// types (discovered outside the tagging API). Keep this list in sync with the
// fanouts in aws_*_fanout.go / aws_fanout*.go and the gap-fillers.
var extraCoveredTypes = []string{
	// security-group rule fanout
	"aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
	// retypeSentinel targets -- never independently register()'d, only
	// ever produced by retyping from their non-default counterpart
	"aws_default_network_acl", "aws_default_vpc",
	// service-discovery namespace retype targets (registered under
	// aws_service_discovery_http_namespace, redirected via retypeSentinel)
	"aws_service_discovery_private_dns_namespace", "aws_service_discovery_public_dns_namespace",
	// datasync location retype targets (registered under
	// aws_datasync_location_s3, redirected via retypeSentinel)
	"aws_datasync_location_nfs", "aws_datasync_location_efs",
	// appconfig application fanout
	"aws_appconfig_environment", "aws_appconfig_configuration_profile",
	// gap-filled account/global-service singletons with no arnToTF path
	"aws_route53_delegation_set", "aws_route53_query_log",
	// guardduty detector fanout
	"aws_guardduty_detector_feature",
	// securityhub gap-fillers
	"aws_securityhub_account", "aws_securityhub_finding_aggregator", "aws_securityhub_standards_subscription",
	"aws_securityhub_standards_control", "aws_securityhub_action_target",
	"aws_securityhub_organization_configuration", "aws_securityhub_member",
	// guardduty fanout
	"aws_guardduty_ipset", "aws_guardduty_threatintelset", "aws_guardduty_member",
	// ebs gap-filler
	"aws_ebs_encryption_by_default", "aws_ebs_default_kms_key",
	// cloudwatch logs gap-fillers
	"aws_cloudwatch_log_resource_policy", "aws_cloudwatch_log_account_policy",
	// iam gap-fillers
	"aws_iam_account_password_policy", "aws_iam_account_alias",
	"aws_iam_access_key", "aws_iam_signing_certificate", "aws_iam_virtual_mfa_device",
	// route53 resolver firewall rule group / query log config fanouts
	"aws_route53_resolver_firewall_rule", "aws_route53_resolver_firewall_rule_group_association",
	"aws_route53_resolver_query_log_config_association",
	// transit gateway peering attachment retype target (registered under
	// aws_ec2_transit_gateway_vpc_attachment, redirected via retypeSentinel)
	"aws_ec2_transit_gateway_peering_attachment",
	// transfer user fanout
	"aws_transfer_ssh_key",
	// DX virtual interface retype target (registered under
	// aws_dx_private_virtual_interface, redirected via retypeSentinel)
	"aws_dx_public_virtual_interface",
	"aws_ecr_registry_policy", "aws_ecr_replication_configuration", "aws_ecr_pull_through_cache_rule",
	"aws_backup_region_settings",
	"aws_ssm_resource_data_sync", "aws_ssm_service_setting",
	"aws_ses_receipt_rule_set",
	// sesv2 email identity fanout
	"aws_sesv2_email_identity_policy",
	// wafv2 web acl fanout
	"aws_wafv2_web_acl_logging_configuration",
	// backup vault fanout
	"aws_backup_vault_policy", "aws_backup_vault_notifications",
	// s3 bucket sub-resources
	"aws_s3_bucket_versioning", "aws_s3_bucket_server_side_encryption_configuration",
	"aws_s3_bucket_public_access_block", "aws_s3_bucket_policy", "aws_s3_bucket_ownership_controls",
	"aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_cors_configuration",
	"aws_s3_bucket_website_configuration", "aws_s3_bucket_logging",
	"aws_s3_bucket_accelerate_configuration", "aws_s3_bucket_request_payment_configuration",
	// iam attachments / inline policies
	"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment",
	"aws_iam_role_policy", "aws_iam_user_policy",
	// eventbridge / route53 / sns fanouts
	"aws_cloudwatch_event_target", "aws_route53_record", "aws_sns_topic_subscription",
	"aws_sns_topic_policy",
	// lb listener rules
	"aws_lb_listener_rule",
	// cloudfront (custom hydrator, not registry-registered)
	"aws_cloudfront_distribution",
	// lambda fanouts
	"aws_lambda_event_source_mapping", "aws_lambda_alias", "aws_lambda_permission",
	"aws_lambda_function_url", "aws_lambda_function_event_invoke_config",
	"aws_lambda_provisioned_concurrency_config", "aws_lambda_function_recursion_config",
	// cloudfront gap-fillers
	"aws_cloudfront_origin_access_control", "aws_cloudfront_origin_access_identity",
	"aws_cloudfront_cache_policy", "aws_cloudfront_origin_request_policy",
	"aws_cloudfront_response_headers_policy", "aws_cloudfront_public_key", "aws_cloudfront_key_group",
	// api gateway v1 fanouts + account gap-filler
	"aws_api_gateway_usage_plan_key", "aws_api_gateway_base_path_mapping", "aws_api_gateway_account",
	// neptune cluster parameter group retype target (registered under
	// aws_rds_cluster_parameter_group, redirected via retypeSentinel)
	"aws_neptune_cluster_parameter_group",
	// neptune cluster fanout + event subscription gap-filler
	"aws_neptune_cluster_instance", "aws_neptune_cluster_endpoint", "aws_neptune_event_subscription",
	// vpc ipam pool fanout
	"aws_vpc_ipam_pool_cidr",
	// cloudwatch logs destination gap-filler
	"aws_cloudwatch_log_destination", "aws_cloudwatch_log_destination_policy",
	// config gap-fillers
	"aws_config_retention_configuration", "aws_config_aggregate_authorization",
	// opensearch domain fanout
	"aws_opensearch_domain_policy", "aws_opensearch_vpc_endpoint",
	// route53 zone fanout (dnssec)
	"aws_route53_hosted_zone_dnssec", "aws_route53_key_signing_key",
	// route53 cidr collection gap-filler
	"aws_route53_cidr_collection", "aws_route53_cidr_location",
	// ec2 traffic mirror filter fanout
	"aws_ec2_traffic_mirror_filter_rule",
	// guardduty org gap-filler + detector fanout
	"aws_guardduty_organization_admin_account",
	"aws_guardduty_organization_configuration", "aws_guardduty_organization_configuration_feature",
	// apigatewayv2 fanouts
	"aws_apigatewayv2_stage", "aws_apigatewayv2_route", "aws_apigatewayv2_integration",
	// api gateway v1 fanout
	"aws_api_gateway_resource", "aws_api_gateway_method", "aws_api_gateway_integration",
	"aws_api_gateway_method_response", "aws_api_gateway_integration_response",
	"aws_api_gateway_authorizer", "aws_api_gateway_request_validator",
	"aws_api_gateway_model", "aws_api_gateway_deployment", "aws_api_gateway_stage",
	"aws_api_gateway_gateway_response",
	// cognito fanouts
	"aws_cognito_user_pool_client", "aws_cognito_user_group",
	// kms / ecr / logs / efs fanouts
	"aws_kms_alias", "aws_ecr_lifecycle_policy", "aws_ecr_repository_policy",
	"aws_cloudwatch_log_metric_filter", "aws_cloudwatch_log_subscription_filter",
	"aws_efs_mount_target",
	// sqs / secrets policy fanouts
	"aws_sqs_queue_policy", "aws_secretsmanager_secret_policy",
	// eks fanouts
	"aws_eks_node_group", "aws_eks_fargate_profile", "aws_eks_addon",
	// glue fanout
	"aws_glue_catalog_table",
	// wafv2 association fanout
	"aws_wafv2_web_acl_association",
	// s3 notification / replication
	"aws_s3_bucket_notification", "aws_s3_bucket_replication_configuration",
	// routing / asg / lb / iam membership / cognito domain fanouts
	"aws_route_table_association",
	"aws_autoscaling_policy", "aws_autoscaling_schedule", "aws_autoscaling_lifecycle_hook",
	"aws_lb_target_group_attachment",
	// aws_iam_group_membership deliberately not (re-)added: dropped in favor
	// of aws_iam_user_group_membership alone (see aws_iam_attach.go) -- the
	// two are competing, mutually-exclusive-in-practice ways to model the
	// same real memberships, and the provider's own docs warn against
	// emitting both.
	"aws_iam_user_group_membership",
	"aws_cognito_user_pool_domain",
	"aws_efs_access_point", "aws_secretsmanager_secret_rotation",
	// application auto scaling gap-filler
	"aws_appautoscaling_target", "aws_appautoscaling_policy",
	// config recorder/delivery channel gap-filler
	"aws_config_configuration_recorder", "aws_config_delivery_channel",
	// ssm maintenance window fanout
	"aws_ssm_maintenance_window_target", "aws_ssm_maintenance_window_task",
	// backup plan fanout
	"aws_backup_selection",
	// lb listener certificate fanout
	"aws_lb_listener_certificate",
	// dynamodb global table replica fanout
	"aws_dynamodb_table_replica", "aws_dynamodb_kinesis_streaming_destination", "aws_dynamodb_contributor_insights",
	// transit gateway route table fanout
	"aws_ec2_transit_gateway_route", "aws_ec2_transit_gateway_route_table_association",
	"aws_ec2_transit_gateway_route_table_propagation",
	// guardduty detector fanout
	"aws_guardduty_filter", "aws_guardduty_publishing_destination",
	// msk cluster fanout
	"aws_msk_scram_secret_association",
	// route53 resolver rule fanout
	"aws_route53_resolver_rule_association",
	// s3 bucket satellite fanout
	"aws_s3_bucket_object_lock_configuration", "aws_s3_bucket_intelligent_tiering_configuration",
	"aws_s3_bucket_acl",
}

// wafv2SwitchTypes are the wafv2 types resolved by the special-case in
// ResolveTFType (they have no arnToTF entry).
var wafv2SwitchTypes = []string{
	"aws_wafv2_web_acl", "aws_wafv2_ip_set", "aws_wafv2_regex_pattern_set", "aws_wafv2_rule_group",
}

// CoveredTypes returns every Terraform resource type inherit can emit: direct
// hydrators, arnToTF targets, fanout children, gap-filled types and the wafv2
// special-cases. Sorted, deduplicated.
func CoveredTypes() []string {
	set := map[string]bool{}
	for tf := range registry {
		set[tf] = true
	}
	for _, tf := range arnToTF {
		set[tf] = true
	}
	for _, tf := range extraCoveredTypes {
		set[tf] = true
	}
	for _, tf := range wafv2SwitchTypes {
		set[tf] = true
	}
	out := make([]string, 0, len(set))
	for tf := range set {
		out = append(out, tf)
	}
	sort.Strings(out)
	return out
}
