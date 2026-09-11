// Command coverage reports which AWS Terraform provider resource types inherit
// can emit and which it cannot, grouped by service.
//
//	go run ./internal/tfschema/cmd/coverage            # summary
//	go run ./internal/tfschema/cmd/coverage -md > docs/COVERAGE.md
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/virtualbeck/inherit/internal/hydrate"
	"github.com/virtualbeck/inherit/tfschema"
)

// multiWordServices are provider type prefixes whose "service" is more than one
// underscore-separated token.
var multiWordServices = []string{
	"api_gateway", "apigatewayv2", "vpc_security_group", "s3_bucket", "s3_access",
	"cloudwatch_event", "cloudwatch_log", "resourcegroups", "route53_resolver",
	"route53_recovery", "elastic_beanstalk", "service_discovery", "cognito_identity",
	"cognito_user", "ec2_transit_gateway", "ec2_managed", "ec2_client_vpn",
	"lb_listener", "lb_target_group", "load_balancer", "db_instance", "db_snapshot",
	"rds_cluster", "iam_role", "iam_user", "iam_group", "iam_openid", "iam_saml",
	"secretsmanager_secret", "wafv2_web_acl", "networkfirewall", "network_acl",
	"opensearch", "opensearchserverless", "prometheus", "grafana",
}

// priorities are uncovered types that turn up often in real accounts. Curated;
// only the ones still uncovered are shown in the report.
var priorities = []string{
	"aws_kinesis_firehose_delivery_stream",
	"aws_ecs_capacity_provider",
	"aws_elasticache_user", "aws_elasticache_user_group",
	"aws_secretsmanager_secret_rotation",
	"aws_appconfig_environment", "aws_appconfig_configuration_profile", "aws_appconfig_deployment_strategy",
	"aws_msk_configuration", "aws_msk_scram_secret_association",
	"aws_glue_trigger", "aws_glue_connection", "aws_glue_workflow",
	"aws_lb_listener_certificate", "aws_lb_trust_store",
	"aws_wafv2_web_acl_logging_configuration", "aws_wafv2_ip_set", "aws_wafv2_regex_pattern_set",
	"aws_route53_resolver_rule_association", "aws_route53_query_log", "aws_route53_delegation_set",
	"aws_sfn_activity",
	"aws_dynamodb_table_replica", "aws_dynamodb_kinesis_streaming_destination", "aws_dynamodb_contributor_insights",
	"aws_ecr_registry_policy", "aws_ecr_replication_configuration", "aws_ecr_pull_through_cache_rule",
	"aws_cloudtrail_event_data_store",
	"aws_backup_selection", "aws_backup_vault_policy", "aws_backup_vault_notifications", "aws_backup_region_settings",
	"aws_datasync_location_nfs", "aws_datasync_location_smb", "aws_datasync_location_efs", "aws_datasync_agent",
	"aws_ec2_transit_gateway_route", "aws_ec2_transit_gateway_route_table_association",
	"aws_ec2_transit_gateway_route_table_propagation", "aws_ec2_transit_gateway_peering_attachment",
	"aws_vpc_ipam", "aws_vpc_endpoint_service", "aws_ec2_client_vpn_endpoint", "aws_default_vpc", "aws_default_security_group",
	"aws_config_configuration_recorder", "aws_config_delivery_channel", "aws_config_configuration_aggregator", "aws_config_conformance_pack",
	"aws_guardduty_publishing_destination", "aws_guardduty_filter", "aws_guardduty_detector_feature",
	"aws_securityhub_account", "aws_securityhub_standards_subscription", "aws_securityhub_finding_aggregator",
	"aws_ssm_maintenance_window_target", "aws_ssm_maintenance_window_task", "aws_ssm_resource_data_sync", "aws_ssm_service_setting",
	"aws_apprunner_service", "aws_apprunner_vpc_connector",
	"aws_grafana_workspace", "aws_prometheus_workspace",
	"aws_cloudwatch_composite_alarm", "aws_cloudwatch_dashboard",
	"aws_service_discovery_private_dns_namespace", "aws_service_discovery_public_dns_namespace", "aws_service_discovery_http_namespace",
	"aws_signer_signing_profile",
	"aws_pipes_pipe",
	"aws_ses_domain_identity", "aws_ses_configuration_set", "aws_ses_receipt_rule_set",
	"aws_sesv2_dedicated_ip_pool", "aws_sesv2_email_identity_policy",
	"aws_transfer_user", "aws_transfer_ssh_key",
	"aws_dx_virtual_interface", "aws_dx_private_virtual_interface", "aws_dx_public_virtual_interface",
	"aws_organizations_organizational_unit", "aws_organizations_policy", "aws_organizations_account",
}

func serviceOf(tf string) string {
	name := strings.TrimPrefix(tf, "aws_")
	for _, p := range multiWordServices {
		if name == p || strings.HasPrefix(name, p+"_") {
			return p
		}
	}
	if i := strings.IndexByte(name, '_'); i >= 0 {
		return name[:i]
	}
	return name
}

func main() {
	md := flag.Bool("md", false, "emit a Markdown report")
	flag.Parse()

	sch, err := tfschema.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	all := make([]string, 0, len(sch.Resources))
	for tf := range sch.Resources {
		all = append(all, tf)
	}
	sort.Strings(all)

	covered := map[string]bool{}
	for _, tf := range hydrate.CoveredTypes() {
		covered[tf] = true
	}

	type svc struct {
		name           string
		covered, uncov []string
	}
	bySvc := map[string]*svc{}
	for _, tf := range all {
		s := serviceOf(tf)
		if bySvc[s] == nil {
			bySvc[s] = &svc{name: s}
		}
		if covered[tf] {
			bySvc[s].covered = append(bySvc[s].covered, tf)
		} else {
			bySvc[s].uncov = append(bySvc[s].uncov, tf)
		}
	}
	svcs := make([]*svc, 0, len(bySvc))
	for _, s := range bySvc {
		svcs = append(svcs, s)
	}
	sort.Slice(svcs, func(i, j int) bool {
		if len(svcs[i].uncov) != len(svcs[j].uncov) {
			return len(svcs[i].uncov) > len(svcs[j].uncov)
		}
		return svcs[i].name < svcs[j].name
	})

	totalCov := 0
	for _, tf := range all {
		if covered[tf] {
			totalCov++
		}
	}

	w := os.Stdout
	if *md {
		fmt.Fprintf(w, "# inherit resource coverage\n\n")
		fmt.Fprintf(w, "Generated by `go run ./internal/tfschema/cmd/coverage -md`.\n\n")
		fmt.Fprintf(w, "Provider schema: **%d** resource types. inherit can emit **%d** (%.0f%%).\n\n",
			len(all), totalCov, 100*float64(totalCov)/float64(len(all)))
		fmt.Fprintf(w, "A service is **partial** if inherit covers some of its types, **absent** if none.\n")
		fmt.Fprintf(w, "Uncovered types in a *partial* service are the cheap wins: the SDK client and\n")
		fmt.Fprintf(w, "discovery path already exist.\n\n")

		fmt.Fprintf(w, "## Priority gaps\n\n")
		fmt.Fprintf(w, "Curated: uncovered types that are common in real accounts.\n\n")
		anyPri := false
		for _, tf := range priorities {
			if _, real := sch.Resources[tf]; real && !covered[tf] {
				fmt.Fprintf(w, "- [ ] %s\n", tf)
				anyPri = true
			}
		}
		if !anyPri {
			fmt.Fprintf(w, "_(none outstanding)_\n")
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "## Partial services (some coverage, gaps remain)\n\n")
		for _, s := range svcs {
			if len(s.covered) == 0 || len(s.uncov) == 0 {
				continue
			}
			fmt.Fprintf(w, "### %s  (%d/%d)\n\n", s.name, len(s.covered), len(s.covered)+len(s.uncov))
			for _, tf := range s.uncov {
				fmt.Fprintf(w, "- [ ] %s\n", tf)
			}
			fmt.Fprintln(w)
		}

		fmt.Fprintf(w, "## Absent services (no coverage)\n\n")
		fmt.Fprintf(w, "| service | types |\n|---|---|\n")
		for _, s := range svcs {
			if len(s.covered) != 0 || len(s.uncov) == 0 {
				continue
			}
			fmt.Fprintf(w, "| %s | %d |\n", s.name, len(s.uncov))
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "<details><summary>absent service types</summary>\n\n")
		for _, s := range svcs {
			if len(s.covered) != 0 || len(s.uncov) == 0 {
				continue
			}
			fmt.Fprintf(w, "**%s**: %s\n\n", s.name, strings.Join(s.uncov, ", "))
		}
		fmt.Fprintf(w, "</details>\n")
		return
	}

	fmt.Fprintf(w, "provider types: %d   covered: %d (%.0f%%)\n\n", len(all), totalCov,
		100*float64(totalCov)/float64(len(all)))
	fmt.Fprintf(w, "%-28s cov/total\n", "service")
	for _, s := range svcs {
		mark := " "
		if len(s.covered) > 0 {
			mark = "~"
		}
		fmt.Fprintf(w, "%s %-26s %d/%d\n", mark, s.name, len(s.covered), len(s.covered)+len(s.uncov))
	}
}
