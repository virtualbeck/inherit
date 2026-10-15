package hydrate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_wafv2_web_acl", hydrateWAFWebACL)
	register("aws_wafv2_rule_group", hydrateWAFRuleGroup)
	registerFanout("aws_wafv2_web_acl", fanoutWAFAssociations)
}

// wafScope derives API scope and client region.
func wafScope(r model.Resource) (wafv2types.Scope, string) {
	if r.Type == "global" {
		return wafv2types.ScopeCloudfront, "us-east-1"
	}
	region := r.Region
	if region == "" {
		region = "us-east-1"
	}
	return wafv2types.ScopeRegional, region
}

func wafVisibility(v *wafv2types.VisibilityConfig) map[string]any {
	if v == nil {
		return nil
	}
	return map[string]any{
		"cloudwatch_metrics_enabled": v.CloudWatchMetricsEnabled,
		"metric_name":                aws.ToString(v.MetricName),
		"sampled_requests_enabled":   v.SampledRequestsEnabled,
	}
}

func wafCustomBodies(m map[string]wafv2types.CustomResponseBody) []any {
	var out []any
	for k, b := range m {
		out = append(out, map[string]any{
			"key":          k,
			"content":      aws.ToString(b.Content),
			"content_type": string(b.ContentType),
		})
	}
	return out
}

func wafDefaultAction(a *wafv2types.DefaultAction) map[string]any {
	if a == nil {
		return nil
	}
	switch {
	case a.Allow != nil:
		return map[string]any{"allow": map[string]any{}}
	case a.Block != nil:
		return map[string]any{"block": map[string]any{}}
	}
	return nil
}

// AGENTCORE_GATEWAY has no schema counterpart; skipped.
var wafAssociationConfigResourceKeys = map[string]string{
	"CLOUDFRONT":               "cloudfront",
	"API_GATEWAY":              "api_gateway",
	"COGNITO_USER_POOL":        "cognito_user_pool",
	"APP_RUNNER_SERVICE":       "app_runner_service",
	"VERIFIED_ACCESS_INSTANCE": "verified_access_instance",
}

func wafAssociationConfig(a *wafv2types.AssociationConfig) map[string]any {
	if a == nil || len(a.RequestBody) == 0 {
		return nil
	}
	rb := map[string]any{}
	for k, v := range a.RequestBody {
		attr, ok := wafAssociationConfigResourceKeys[k]
		if !ok {
			continue
		}
		rb[attr] = []any{map[string]any{"default_size_inspection_limit": string(v.DefaultSizeInspectionLimit)}}
	}
	if len(rb) == 0 {
		return nil
	}
	return map[string]any{"request_body": []any{rb}}
}

func wafImmunityTime(p *wafv2types.ImmunityTimeProperty) map[string]any {
	if p == nil || p.ImmunityTime == nil {
		return nil
	}
	return map[string]any{"immunity_time_property": []any{map[string]any{"immunity_time": *p.ImmunityTime}}}
}

func wafDataProtectionConfig(c *wafv2types.DataProtectionConfig) map[string]any {
	if c == nil || len(c.DataProtections) == 0 {
		return nil
	}
	var dps []any
	for _, dp := range c.DataProtections {
		m := map[string]any{
			"action":                     string(dp.Action),
			"exclude_rate_based_details": dp.ExcludeRateBasedDetails,
			"exclude_rule_match_details": dp.ExcludeRuleMatchDetails,
		}
		if f := dp.Field; f != nil {
			fm := map[string]any{"field_type": string(f.FieldType)}
			if len(f.FieldKeys) > 0 {
				fm["field_keys"] = toAny(f.FieldKeys)
			}
			m["field"] = []any{fm}
		}
		dps = append(dps, m)
	}
	return map[string]any{"data_protection": dps}
}

func hydrateWAFWebACL(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	scope, region := wafScope(r)
	arn := r.ARN
	out, err := wafv2.NewFromConfig(c.Cfg(region)).GetWebACL(ctx, &wafv2.GetWebACLInput{ARN: &arn})
	if err != nil {
		return nil, err
	}
	a := out.WebACL
	if a == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"name":  aws.ToString(a.Name),
		"scope": string(scope),
	}
	if v := aws.ToString(a.Description); v != "" {
		cfg["description"] = v
	}
	if da := wafDefaultAction(a.DefaultAction); da != nil {
		cfg["default_action"] = da
	}
	if vc := wafVisibility(a.VisibilityConfig); vc != nil {
		cfg["visibility_config"] = vc
	}
	if b := wafCustomBodies(a.CustomResponseBodies); len(b) > 0 {
		cfg["custom_response_body"] = b
	}
	if len(a.TokenDomains) > 0 {
		cfg["token_domains"] = toAny(a.TokenDomains)
	}
	if ac := wafAssociationConfig(a.AssociationConfig); ac != nil {
		cfg["association_config"] = []any{ac}
	}
	if cc := a.CaptchaConfig; cc != nil {
		if it := wafImmunityTime(cc.ImmunityTimeProperty); it != nil {
			cfg["captcha_config"] = []any{it}
		}
	}
	if cc := a.ChallengeConfig; cc != nil {
		if it := wafImmunityTime(cc.ImmunityTimeProperty); it != nil {
			cfg["challenge_config"] = []any{it}
		}
	}
	if dp := wafDataProtectionConfig(a.DataProtectionConfig); dp != nil {
		cfg["data_protection_config"] = []any{dp}
	}
	// recursive rules go verbatim through rule_json
	if len(a.Rules) > 0 {
		j, err := json.Marshal(a.Rules)
		if err != nil {
			return nil, err
		}
		cfg["rule_json"] = string(j)
	}
	return cfg, nil
}

func hydrateWAFRuleGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id, name, scope := parseWAFArn(r)
	_, region := wafScope(r)
	out, err := wafv2.NewFromConfig(c.Cfg(region)).GetRuleGroup(ctx, &wafv2.GetRuleGroupInput{
		Id: &id, Name: &name, Scope: scope,
	})
	if err != nil {
		return nil, err
	}
	g := out.RuleGroup
	if g == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"name":     aws.ToString(g.Name),
		"scope":    string(scope),
		"capacity": g.Capacity,
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	if vc := wafVisibility(g.VisibilityConfig); vc != nil {
		cfg["visibility_config"] = vc
	}
	if b := wafCustomBodies(g.CustomResponseBodies); len(b) > 0 {
		cfg["custom_response_body"] = b
	}
	if len(g.Rules) > 0 {
		j, err := json.Marshal(g.Rules)
		if err != nil {
			return nil, err
		}
		cfg["rules_json"] = string(j)
	}
	return cfg, nil
}

func fanoutWAFAssociations(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	scope, region := wafScope(parent)
	if scope != wafv2types.ScopeRegional {
		return nil, nil // CloudFront scope associates via the distribution
	}
	cl := wafv2.NewFromConfig(c.Cfg(region))
	types := []wafv2types.ResourceType{
		"APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC",
		"COGNITO_USER_POOL", "APP_RUNNER_SERVICE", "VERIFIED_ACCESS_INSTANCE", "AMPLIFY",
	}
	seen := map[string]bool{}
	var kids []model.Resource
	for _, rt := range types {
		out, err := cl.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
			WebACLArn: &parent.ARN, ResourceType: rt,
		})
		if err != nil {
			continue
		}
		for _, resArn := range out.ResourceArns {
			if seen[resArn] {
				continue
			}
			seen[resArn] = true
			kids = append(kids, model.Resource{
				Service: "wafv2", Type: "webacl-association", TFType: "aws_wafv2_web_acl_association",
				Region: parent.Region, Account: parent.Account,
				ID:     parent.ARN + "," + resArn,
				Config: map[string]any{"web_acl_arn": parent.ARN, "resource_arn": resArn},
			})
		}
	}

	if lc, err := cl.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: &parent.ARN}); err == nil && lc.LoggingConfiguration != nil {
		sch, serr := schemaFor("aws_wafv2_web_acl_logging_configuration")
		if serr == nil {
			// Filters maps to filter
			if cfg, gerr := Generic(lc.LoggingConfiguration, sch, map[string]string{"filters": "filter"}); gerr == nil && len(cfg) > 0 {
				kids = append(kids, model.Resource{
					Service: "wafv2", Type: "webacl-logging-configuration", TFType: "aws_wafv2_web_acl_logging_configuration",
					Region: parent.Region, Account: parent.Account,
					ID: parent.ARN, ImportID: parent.ARN,
					Config: cfg,
				})
			}
		}
	}

	return kids, nil
}
