package hydrate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/virtualbeck/inherit/model"
	"github.com/virtualbeck/inherit/tfschema"
)

// Hydrator fetches the full configuration of one resource and returns it as a
// Terraform-attribute-shaped map. It must only call read-only APIs.
type Hydrator func(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error)

var registry = map[string]Hydrator{}

// RegionResolver looks up the real region for a resource whose ARN carries
// none (S3 buckets: `arn:aws:s3:::bucket`, no region segment) so the emitter
// can pin it to the right aliased provider instead of silently defaulting to
// the module's default region.
type RegionResolver func(ctx context.Context, c *Clients, r model.Resource) (string, error)

var regionResolvers = map[string]RegionResolver{}

// registerRegionResolver wires a region resolver to a Terraform resource
// type whose discovered ARN doesn't carry a region.
func registerRegionResolver(tfType string, f RegionResolver) {
	if _, dup := regionResolvers[tfType]; dup {
		panic("hydrate: duplicate region resolver for " + tfType)
	}
	regionResolvers[tfType] = f
}

// retypeSentinel is a reserved Config key a Hydrator may set to redirect its
// resource to a different Terraform type once hydration reveals something
// ResolveTFType's ARN-only classification couldn't have known -- e.g. a
// network ACL that turns out to be a VPC's default one, which the provider
// insists on importing as aws_default_network_acl, not aws_network_acl, and
// rejects outright otherwise. Run() pops it and reassigns r.TFType before
// treating the resource as hydrated.
const retypeSentinel = "__inherit_retype_as"

// register wires a hydrator to a Terraform resource type. Called from init() in
// the per-service files.
func register(tfType string, h Hydrator) {
	if _, dup := registry[tfType]; dup {
		panic("hydrate: duplicate hydrator for " + tfType)
	}
	registry[tfType] = h
}

// hydrateRegistered runs tfType's already-registered hydrator and applies
// retypeSentinel if the hydrator sets one, returning the resource's final
// type alongside its config. Gap-fillers need this (not a bare
// registry[tfType] lookup) because they run outside Run()'s own per-resource
// loop -- the only other place retypeSentinel is handled -- so calling the
// hydrator directly would silently leave a retyping hydrator's sentinel key
// sitting unprocessed in cfg and the resource's TFType never updated (e.g.
// gapFillDefaultNetwork's aws_vpc entries would keep emitting as plain
// aws_vpc despite hydrateVPC's own default-VPC retype firing correctly).
func hydrateRegistered(ctx context.Context, c *Clients, r model.Resource) (cfg map[string]any, finalType string, err error) {
	h, ok := registry[r.TFType]
	if !ok {
		return nil, r.TFType, fmt.Errorf("no hydrator registered for %s", r.TFType)
	}
	cfg, err = h(ctx, c, r)
	if err != nil {
		return nil, r.TFType, err
	}
	finalType = r.TFType
	if newType, ok := cfg[retypeSentinel].(string); ok {
		delete(cfg, retypeSentinel)
		finalType = newType
	}
	return cfg, finalType, nil
}

// arnToTF maps (ARN service, ARN resource-type) to a Terraform resource type.
// Discovery fills Resource.Service/Type from the ARN; this turns that into the
// provider's type name.
var arnToTF = map[[2]string]string{
	{"ec2", "vpc"}:                                   "aws_vpc",
	{"ec2", "subnet"}:                                "aws_subnet",
	{"ec2", "security-group"}:                        "aws_security_group",
	{"ec2", "route-table"}:                           "aws_route_table",
	{"ec2", "internet-gateway"}:                      "aws_internet_gateway",
	{"ec2", "natgateway"}:                            "aws_nat_gateway",
	{"ec2", "elastic-ip"}:                            "aws_eip",
	{"ec2", "network-acl"}:                           "aws_network_acl",
	{"ec2", "network-insights-path"}:                 "aws_ec2_network_insights_path",
	{"ec2", "capacity-reservation"}:                  "aws_ec2_capacity_reservation",
	{"ec2", "instance-connect-endpoint"}:             "aws_ec2_instance_connect_endpoint",
	{"ec2", "carrier-gateway"}:                       "aws_ec2_carrier_gateway",
	{"ec2", "dedicated-host"}:                        "aws_ec2_host",
	{"ec2", "traffic-mirror-filter"}:                 "aws_ec2_traffic_mirror_filter",
	{"ec2", "traffic-mirror-session"}:                "aws_ec2_traffic_mirror_session",
	{"ec2", "traffic-mirror-target"}:                 "aws_ec2_traffic_mirror_target",
	{"cloudfront", "vpcorigin"}:                      "aws_cloudfront_vpc_origin",
	{"cloudfront", "function"}:                       "aws_cloudfront_function",
	{"dlm", "policy"}:                                "aws_dlm_lifecycle_policy",
	{"ec2", "vpc-endpoint"}:                          "aws_vpc_endpoint",
	{"ec2", "vpc-endpoint-service"}:                  "aws_vpc_endpoint_service",
	{"ec2", "dhcp-options"}:                          "aws_vpc_dhcp_options",
	{"ec2", "instance"}:                              "aws_instance",
	{"ec2", "transit-gateway"}:                       "aws_ec2_transit_gateway",
	{"ec2", "transit-gateway-attachment"}:            "aws_ec2_transit_gateway_vpc_attachment",
	{"ec2", "vpn-gateway"}:                           "aws_vpn_gateway",
	{"ec2", "customer-gateway"}:                      "aws_customer_gateway",
	{"ec2", "vpn-connection"}:                        "aws_vpn_connection",
	{"codepipeline", ""}:                             "aws_codepipeline",
	{"glue", "job"}:                                  "aws_glue_job",
	{"glue", "crawler"}:                              "aws_glue_crawler",
	{"glue", "trigger"}:                              "aws_glue_trigger",
	{"glue", "connection"}:                           "aws_glue_connection",
	{"glue", "workflow"}:                             "aws_glue_workflow",
	{"elasticmapreduce", "cluster"}:                  "aws_emr_cluster",
	{"batch", "compute-environment"}:                 "aws_batch_compute_environment",
	{"batch", "job-queue"}:                           "aws_batch_job_queue",
	{"globalaccelerator", "accelerator"}:             "aws_globalaccelerator_accelerator",
	{"dms", "rep"}:                                   "aws_dms_replication_instance",
	{"route53resolver", "resolver-endpoint"}:         "aws_route53_resolver_endpoint",
	{"route53resolver", "firewall-rule-group"}:       "aws_route53_resolver_firewall_rule_group",
	{"route53resolver", "firewall-domain-list"}:      "aws_route53_resolver_firewall_domain_list",
	{"route53resolver", "resolver-query-log-config"}: "aws_route53_resolver_query_log_config",
	{"datasync", "task"}:                             "aws_datasync_task",
	// every DataSync location type shares this one ARN resource segment;
	// hydrateDataSyncLocation determines the real type from ListLocations'
	// own LocationUri and retypes accordingly.
	{"datasync", "location"}:     "aws_datasync_location_s3",
	{"datasync", "agent"}:        "aws_datasync_agent",
	{"directconnect", "dxcon"}:   "aws_dx_connection",
	{"directconnect", "dxvif"}:   "aws_dx_private_virtual_interface",
	{"organizations", "ou"}:      "aws_organizations_organizational_unit",
	{"organizations", "policy"}:  "aws_organizations_policy",
	{"organizations", "account"}: "aws_organizations_account",
	{"rds", "pg"}:                "aws_db_parameter_group",
	// Neptune cluster parameter groups share this exact ARN segment
	// (rds:cluster-pg:name) with RDS/Aurora -- hydrateRDSClusterParamGroup
	// tries RDS first and falls back to Neptune + retypeSentinel on a
	// DBClusterParameterGroupNotFoundFault.
	{"rds", "cluster-pg"}:                          "aws_rds_cluster_parameter_group",
	{"redshift", "parametergroup"}:                 "aws_redshift_parameter_group",
	{"redshift", "subnetgroup"}:                    "aws_redshift_subnet_group",
	{"redshift", "eventsubscription"}:              "aws_redshift_event_subscription",
	{"rds", "og"}:                                  "aws_db_option_group",
	{"elasticache", "subnetgroup"}:                 "aws_elasticache_subnet_group",
	{"elasticache", "parametergroup"}:              "aws_elasticache_parameter_group",
	{"servicediscovery", "service"}:                "aws_service_discovery_service",
	{"signer", "signing-profiles"}:                 "aws_signer_signing_profile",
	{"pipes", "pipe"}:                              "aws_pipes_pipe",
	{"servicediscovery", "namespace"}:              "aws_service_discovery_http_namespace",
	{"elasticbeanstalk", "application"}:            "aws_elastic_beanstalk_application",
	{"elasticbeanstalk", "environment"}:            "aws_elastic_beanstalk_environment",
	{"cognito-identity", "identitypool"}:           "aws_cognito_identity_pool",
	{"ec2", "vpc-peering-connection"}:              "aws_vpc_peering_connection",
	{"ec2", "ipam"}:                                "aws_vpc_ipam",
	{"ec2", "ipam-pool"}:                           "aws_vpc_ipam_pool",
	{"ec2", "ipam-scope"}:                          "aws_vpc_ipam_scope",
	{"ec2", "ipam-resource-discovery"}:             "aws_vpc_ipam_resource_discovery",
	{"ec2", "ipam-resource-discovery-association"}: "aws_vpc_ipam_resource_discovery_association",
	{"ec2", "client-vpn-endpoint"}:                 "aws_ec2_client_vpn_endpoint",
	{"ec2", "transit-gateway-route-table"}:         "aws_ec2_transit_gateway_route_table",
	{"ses", "identity"}:                            "aws_sesv2_email_identity",
	{"ses", "configuration-set"}:                   "aws_sesv2_configuration_set",
	{"ses", "dedicated-ip-pool"}:                   "aws_sesv2_dedicated_ip_pool",
	{"network-firewall", "firewall"}:               "aws_networkfirewall_firewall",
	{"ram", "resource-share"}:                      "aws_ram_resource_share",
	{"directconnect", "dx-gateway"}:                "aws_dx_gateway",
	{"ec2", "key-pair"}:                            "aws_key_pair",
	{"ec2", "volume"}:                              "aws_ebs_volume",
	{"ec2", "vpc-flow-log"}:                        "aws_flow_log",
	{"ec2", "prefix-list"}:                         "aws_ec2_managed_prefix_list",
	{"route53resolver", "resolver-rule"}:           "aws_route53_resolver_rule",
	{"ssm", "association"}:                         "aws_ssm_association",
	{"cloudformation", "stack"}:                    "aws_cloudformation_stack",
	{"ec2", "network-interface"}:                   "aws_network_interface",
	{"events", "event-bus"}:                        "aws_cloudwatch_event_bus",
	{"scheduler", "schedule-group"}:                "aws_scheduler_schedule_group",
	{"scheduler", "schedule"}:                      "aws_scheduler_schedule",
	{"ssm", "maintenancewindow"}:                   "aws_ssm_maintenance_window",
	{"ssm", "patchbaseline"}:                       "aws_ssm_patch_baseline",
	{"config", "config-rule"}:                      "aws_config_config_rule",
	{"guardduty", "detector"}:                      "aws_guardduty_detector",
	{"access-analyzer", "analyzer"}:                "aws_accessanalyzer_analyzer",
	{"lambda", "layer"}:                            "aws_lambda_layer_version",
	{"lambda", "code-signing-config"}:              "aws_lambda_code_signing_config",
	{"airflow", "environment"}:                     "aws_mwaa_environment",
	{"memorydb", "cluster"}:                        "aws_memorydb_cluster",
	{"appconfig", "application"}:                   "aws_appconfig_application",
	{"appconfig", "deploymentstrategy"}:            "aws_appconfig_deployment_strategy",
	{"resource-explorer-2", "index"}:               "aws_resourceexplorer2_index",
	{"resource-explorer-2", "view"}:                "aws_resourceexplorer2_view",
	{"cloudformation", "stackset"}:                 "aws_cloudformation_stack_set",
	{"s3", ""}:                                     "aws_s3_bucket",
	{"rds", "db"}:                                  "aws_db_instance",
	{"rds", "cluster"}:                             "aws_rds_cluster",
	{"rds", "subgrp"}:                              "aws_db_subnet_group",
	{"lambda", "function"}:                         "aws_lambda_function",
	{"elasticloadbalancing", "loadbalancer"}:       "aws_lb",
	{"elasticloadbalancing", "targetgroup"}:        "aws_lb_target_group",
	{"elasticloadbalancing", "listener"}:           "aws_lb_listener",
	{"iam", "role"}:                                "aws_iam_role",
	{"iam", "policy"}:                              "aws_iam_policy",
	{"iam", "user"}:                                "aws_iam_user",
	{"iam", "group"}:                               "aws_iam_group",
	{"iam", "instance-profile"}:                    "aws_iam_instance_profile",
	{"sns", ""}:                                    "aws_sns_topic",
	{"sqs", ""}:                                    "aws_sqs_queue",
	{"dynamodb", "table"}:                          "aws_dynamodb_table",
	{"kms", "key"}:                                 "aws_kms_key",
	{"logs", "log-group"}:                          "aws_cloudwatch_log_group",
	{"cloudwatch", "alarm"}:                        "aws_cloudwatch_metric_alarm",
	{"ecs", "cluster"}:                             "aws_ecs_cluster",
	{"ecs", "service"}:                             "aws_ecs_service",
	{"elasticache", "cluster"}:                     "aws_elasticache_cluster",
	{"elasticache", "replicationgroup"}:            "aws_elasticache_replication_group",
	{"secretsmanager", "secret"}:                   "aws_secretsmanager_secret",
	{"apigateway", ""}:                             "aws_api_gateway_rest_api",
	{"events", "rule"}:                             "aws_cloudwatch_event_rule",
	{"ecr", "repository"}:                          "aws_ecr_repository",
	{"acm", "certificate"}:                         "aws_acm_certificate",
	{"ec2", "launch-template"}:                     "aws_launch_template",
	{"autoscaling", "autoScalingGroup"}:            "aws_autoscaling_group",
	{"route53", "hostedzone"}:                      "aws_route53_zone",
	{"elasticfilesystem", "file-system"}:           "aws_efs_file_system",
	{"states", "stateMachine"}:                     "aws_sfn_state_machine",
	{"states", "activity"}:                         "aws_sfn_activity",
	{"ssm", "parameter"}:                           "aws_ssm_parameter",
	{"cognito-idp", "userpool"}:                    "aws_cognito_user_pool",
	{"apigateway", "restapis"}:                     "aws_api_gateway_rest_api",
	{"apigateway", "apis"}:                         "aws_apigatewayv2_api",
	{"apigateway", "apikeys"}:                      "aws_api_gateway_api_key",
	{"apigateway", "usageplans"}:                   "aws_api_gateway_usage_plan",
	{"apigateway", "clientcertificates"}:           "aws_api_gateway_client_certificate",
	// vpclinks/domainnames: v1 REST API and v2 HTTP API both use these same
	// ARN resource segments for what may be the identical underlying AWS
	// object (a custom domain name in particular is shared across REST and
	// HTTP APIs via separate mapping resources). Only aws_api_gateway_*
	// (v1) is implemented so far -- adding aws_apigatewayv2_vpc_link/
	// domain_name later needs the same "pick one, don't double-emit"
	// judgment call already made for SES v1/v2 and IAM group membership.
	{"apigateway", "vpclinks"}:         "aws_api_gateway_vpc_link",
	{"apigateway", "domainnames"}:      "aws_api_gateway_domain_name",
	{"kinesis", "stream"}:              "aws_kinesis_stream",
	{"glue", "database"}:               "aws_glue_catalog_database",
	{"cloudwatch", "dashboard"}:        "aws_cloudwatch_dashboard",
	{"codebuild", "project"}:           "aws_codebuild_project",
	{"athena", "workgroup"}:            "aws_athena_workgroup",
	{"ecs", "task-definition"}:         "aws_ecs_task_definition",
	{"cloudtrail", "trail"}:            "aws_cloudtrail",
	{"cloudtrail", "eventdatastore"}:   "aws_cloudtrail_event_data_store",
	{"backup", "backup-vault"}:         "aws_backup_vault",
	{"backup", "backup-plan"}:          "aws_backup_plan",
	{"eks", "cluster"}:                 "aws_eks_cluster",
	{"ssm", "document"}:                "aws_ssm_document",
	{"es", "domain"}:                   "aws_opensearch_domain",
	{"sagemaker", "notebook-instance"}: "aws_sagemaker_notebook_instance",
	{"kafka", "cluster"}:               "aws_msk_cluster",
	{"config", "config-aggregator"}:    "aws_config_configuration_aggregator",
	{"kafka", "configuration"}:         "aws_msk_configuration",
	{"route53", "healthcheck"}:         "aws_route53_health_check",
	{"iam", "oidc-provider"}:           "aws_iam_openid_connect_provider",
	{"iam", "saml-provider"}:           "aws_iam_saml_provider",
	{"cloudfront", "distribution"}:     "aws_cloudfront_distribution",
	{"redshift", "cluster"}:            "aws_redshift_cluster",
	{"transfer", "server"}:             "aws_transfer_server",
	{"transfer", "user"}:               "aws_transfer_user",
	{"transfer", "agreement"}:          "aws_transfer_agreement",
	{"transfer", "connector"}:          "aws_transfer_connector",
	{"transfer", "certificate"}:        "aws_transfer_certificate",
	{"transfer", "profile"}:            "aws_transfer_profile",
	{"grafana", "workspaces"}:          "aws_grafana_workspace",
	{"aps", "workspace"}:               "aws_prometheus_workspace",
	{"apprunner", "service"}:           "aws_apprunner_service",
	{"apprunner", "vpcconnector"}:      "aws_apprunner_vpc_connector",
	{"mq", "broker"}:                   "aws_mq_broker",
	{"appsync", "apis"}:                "aws_appsync_graphql_api",
	{"firehose", "deliverystream"}:     "aws_kinesis_firehose_delivery_stream",
	{"ecs", "capacity-provider"}:       "aws_ecs_capacity_provider",
	{"rds", "db-proxy"}:                "aws_db_proxy",
	{"dms", "endpoint"}:                "aws_dms_endpoint",
	{"dms", "task"}:                    "aws_dms_replication_task",
	{"dms", "subgrp"}:                  "aws_dms_replication_subnet_group",
	{"elasticache", "user"}:            "aws_elasticache_user",
	{"elasticache", "usergroup"}:       "aws_elasticache_user_group",
}

// ResolveTFType returns the Terraform type for a discovered resource, or "".
func ResolveTFType(r model.Resource) string {
	if r.Service == "wafv2" {
		// ARN resource is "<scope>/<kind>/<name>/<id>"; Type holds the scope,
		// so the kind is the first segment of the id.
		kind, _, _ := strings.Cut(r.ID, "/")
		switch kind {
		case "webacl":
			return "aws_wafv2_web_acl"
		case "ipset":
			return "aws_wafv2_ip_set"
		case "regexpatternset":
			return "aws_wafv2_regex_pattern_set"
		case "rulegroup":
			return "aws_wafv2_rule_group"
		}
	}
	return arnToTF[[2]string{r.Service, r.Type}]
}

// Stats summarises a hydration run.
type Stats struct {
	Hydrated   int
	NoHydrator map[string]int // tf type -> count (mapped but no hydrator yet)
	Unmapped   map[string]int // "service.type" -> count
	Errors     []error
}

// Options controls a hydration run.
type Options struct {
	Concurrency int
	OnProgress  func(done, total int)
}

// Run fills r.TFType for every resolvable resource and r.Config for every one
// with a registered hydrator, concurrently.
func Run(ctx context.Context, cfg aws.Config, inv *model.Inventory, opt Options) (Stats, error) {
	if _, err := tfschema.Load(); err != nil { // fail fast if the embedded schema is broken
		return Stats{}, err
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 16
	}
	clients := newClients(cfg)

	st := Stats{NoHydrator: map[string]int{}, Unmapped: map[string]int{}}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, opt.Concurrency)
		done int
	)

	// gap-fillers discover + hydrate resource types the tagging API can't see
	// (application auto scaling, ...); they arrive with TFType and Config set.
	st.Errors = append(st.Errors, runGapFillers(ctx, clients, inv)...)

	for i := range inv.Resources {
		r := &inv.Resources[i]
		if r.Config != nil { // gap-filled already
			continue
		}
		r.TFType = ResolveTFType(*r)

		if r.TFType == "" {
			key := r.Service + "." + r.Type
			mu.Lock()
			st.Unmapped[key]++
			mu.Unlock()
			continue
		}
		h, ok := registry[r.TFType]
		if !ok {
			mu.Lock()
			st.NoHydrator[r.TFType]++
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(r *model.Resource, h Hydrator) {
			defer wg.Done()
			defer func() { <-sem }()

			if r.Region == "" {
				if resolve, ok := regionResolvers[r.TFType]; ok {
					if region, err := resolve(ctx, clients, *r); err == nil && region != "" {
						r.Region = region
					}
				}
			}

			cfgMap, err := h(ctx, clients, *r)
			mu.Lock()
			defer mu.Unlock()
			done++
			if opt.OnProgress != nil {
				opt.OnProgress(done, len(inv.Resources))
			}
			if err != nil {
				st.Errors = append(st.Errors, fmt.Errorf("%s %s: %w", r.TFType, r.ID, err))
				return
			}
			if newType, ok := cfgMap[retypeSentinel].(string); ok {
				delete(cfgMap, retypeSentinel)
				r.TFType = newType
			}
			if len(r.Tags) > 0 {
				cfgMap["tags"] = r.Tags
			}
			r.Config = cfgMap
			st.Hydrated++
		}(r, h)
	}
	wg.Wait()

	// expand split resources (SG rules, ...) from the parents that hydrated,
	// then recount so Hydrated reflects what will actually emit.
	st.Errors = append(st.Errors, runFanout(ctx, clients, inv, opt.Concurrency)...)
	st.Hydrated = 0
	for _, r := range inv.Resources {
		if r.Config != nil {
			st.Hydrated++
		}
	}
	return st, nil
}

// schemaFor is a hydrator helper: the schema block for a tf type, or an error.
func schemaFor(tfType string) (*tfschema.Block, error) {
	sch, err := tfschema.Load()
	if err != nil {
		return nil, err
	}
	b, ok := sch.Resource(tfType)
	if !ok {
		return nil, fmt.Errorf("no schema for %s", tfType)
	}
	return b, nil
}

// SortedCounts flattens a name->count map, count desc then name.
func SortedCounts(m map[string]int) []model.TypeCount {
	out := make([]model.TypeCount, 0, len(m))
	for k, v := range m {
		out = append(out, model.TypeCount{Type: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}
