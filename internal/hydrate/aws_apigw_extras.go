package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	agw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	agwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_api_gateway_api_key", hydrateAPIGatewayAPIKey)
	register("aws_api_gateway_usage_plan", hydrateAPIGatewayUsagePlan)
	registerFanout("aws_api_gateway_usage_plan", fanoutAPIGatewayUsagePlanKeys)
	register("aws_api_gateway_domain_name", hydrateAPIGatewayDomainName)
	registerFanout("aws_api_gateway_domain_name", fanoutAPIGatewayBasePathMappings)
	register("aws_api_gateway_vpc_link", hydrateAPIGatewayVPCLink)
	register("aws_api_gateway_client_certificate", hydrateAPIGatewayClientCertificate)
	registerGapFiller(gapFillAPIGatewayAccount)
}

func hydrateAPIGatewayAPIKey(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := agw.NewFromConfig(c.Cfg(r.Region)).GetApiKey(ctx, &agw.GetApiKeyInput{ApiKey: &id, IncludeValue: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":    aws.ToString(out.Name),
		"enabled": out.Enabled,
	}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(out.CustomerId); v != "" {
		cfg["customer_id"] = v
	}
	if v := aws.ToString(out.Value); v != "" {
		cfg["value"] = v
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

func hydrateAPIGatewayUsagePlan(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	cl := agw.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.GetUsagePlan(ctx, &agw.GetUsagePlanInput{UsagePlanId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Name)}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(out.ProductCode); v != "" {
		cfg["product_code"] = v
	}
	if out.Quota != nil {
		cfg["quota_settings"] = []any{map[string]any{
			"limit": int(out.Quota.Limit), "offset": int(out.Quota.Offset), "period": string(out.Quota.Period),
		}}
	}
	if out.Throttle != nil {
		cfg["throttle_settings"] = []any{map[string]any{
			"burst_limit": int(out.Throttle.BurstLimit), "rate_limit": out.Throttle.RateLimit,
		}}
	}
	if len(out.ApiStages) > 0 {
		var stages []any
		for _, s := range out.ApiStages {
			stage := map[string]any{"api_id": aws.ToString(s.ApiId), "stage": aws.ToString(s.Stage)}
			if len(s.Throttle) > 0 {
				var throttles []any
				for path, t := range s.Throttle {
					throttles = append(throttles, map[string]any{
						"path": path, "burst_limit": int(t.BurstLimit), "rate_limit": t.RateLimit,
					})
				}
				stage["throttle"] = throttles
			}
			stages = append(stages, stage)
		}
		cfg["api_stages"] = stages
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

// fanoutAPIGatewayUsagePlanKeys expands a usage plan into the API keys
// associated with it.
func fanoutAPIGatewayUsagePlanKeys(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := agw.NewFromConfig(c.Cfg(parent.Region))
	planID := parent.ID
	var kids []model.Resource
	position := (*string)(nil)
	for {
		page, err := cl.GetUsagePlanKeys(ctx, &agw.GetUsagePlanKeysInput{UsagePlanId: &planID, Position: position})
		if err != nil {
			return kids, err
		}
		for _, k := range page.Items {
			keyID := aws.ToString(k.Id)
			if keyID == "" {
				continue
			}
			id := planID + "/" + keyID
			kids = append(kids, model.Resource{
				Service: "apigateway", Type: "usageplan-key", TFType: "aws_api_gateway_usage_plan_key",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: map[string]any{
					"usage_plan_id": planID,
					"key_id":        keyID,
					"key_type":      "API_KEY",
				},
			})
		}
		if page.Position == nil || aws.ToString(page.Position) == "" {
			break
		}
		position = page.Position
	}
	return kids, nil
}

func hydrateAPIGatewayDomainName(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := agw.NewFromConfig(c.Cfg(r.Region)).GetDomainName(ctx, &agw.GetDomainNameInput{DomainName: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"domain_name": name}
	if v := aws.ToString(out.CertificateArn); v != "" {
		cfg["certificate_arn"] = v
	}
	if v := aws.ToString(out.CertificateName); v != "" {
		cfg["certificate_name"] = v
	}
	if v := aws.ToString(out.RegionalCertificateArn); v != "" {
		cfg["regional_certificate_arn"] = v
	}
	if v := aws.ToString(out.RegionalCertificateName); v != "" {
		cfg["regional_certificate_name"] = v
	}
	if v := string(out.SecurityPolicy); v != "" {
		cfg["security_policy"] = v
	}
	if v := aws.ToString(out.Policy); v != "" {
		cfg["policy"] = v
	}
	if len(out.EndpointConfiguration.Types) > 0 || len(out.EndpointConfiguration.VpcEndpointIds) > 0 {
		ec := map[string]any{"types": toAny(agwEndpointTypeStrings(out.EndpointConfiguration.Types))}
		if len(out.EndpointConfiguration.VpcEndpointIds) > 0 {
			ec["vpc_endpoint_ids"] = toAny(out.EndpointConfiguration.VpcEndpointIds)
		}
		cfg["endpoint_configuration"] = []any{ec}
	}
	if out.MutualTlsAuthentication != nil {
		mtls := map[string]any{"truststore_uri": aws.ToString(out.MutualTlsAuthentication.TruststoreUri)}
		if v := aws.ToString(out.MutualTlsAuthentication.TruststoreVersion); v != "" {
			mtls["truststore_version"] = v
		}
		cfg["mutual_tls_authentication"] = []any{mtls}
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

func agwEndpointTypeStrings(types []agwtypes.EndpointType) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = string(t)
	}
	return out
}

// fanoutAPIGatewayBasePathMappings expands a custom domain name into its
// base path mappings (which REST API + stage each path routes to).
func fanoutAPIGatewayBasePathMappings(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := agw.NewFromConfig(c.Cfg(parent.Region))
	domain := parent.ID
	var kids []model.Resource
	position := (*string)(nil)
	for {
		page, err := cl.GetBasePathMappings(ctx, &agw.GetBasePathMappingsInput{DomainName: &domain, Position: position})
		if err != nil {
			return kids, err
		}
		for _, m := range page.Items {
			basePath := aws.ToString(m.BasePath)
			// AWS's own API uses the literal string "(none)" for an empty
			// base path, but the provider's import id format wants a bare
			// empty segment there instead ("domain.com/", not
			// "domain.com/(none)") -- confirmed against the real provider
			// source's basePathMappingParseResourceID.
			idPath := basePath
			if idPath == "(none)" {
				idPath = ""
			}
			id := domain + "/" + idPath
			cfg := map[string]any{
				"domain_name": domain,
				"api_id":      aws.ToString(m.RestApiId),
			}
			if basePath != "" && basePath != "(none)" {
				cfg["base_path"] = basePath
			}
			if v := aws.ToString(m.Stage); v != "" {
				cfg["stage_name"] = v
			}
			kids = append(kids, model.Resource{
				Service: "apigateway", Type: "basepathmapping", TFType: "aws_api_gateway_base_path_mapping",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if page.Position == nil || aws.ToString(page.Position) == "" {
			break
		}
		position = page.Position
	}
	return kids, nil
}

func hydrateAPIGatewayVPCLink(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := agw.NewFromConfig(c.Cfg(r.Region)).GetVpcLink(ctx, &agw.GetVpcLinkInput{VpcLinkId: &id})
	if err != nil {
		return nil, err
	}
	if out.Name == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"name":        aws.ToString(out.Name),
		"target_arns": toAny(out.TargetArns),
	}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

func hydrateAPIGatewayClientCertificate(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := agw.NewFromConfig(c.Cfg(r.Region)).GetClientCertificate(ctx, &agw.GetClientCertificateInput{ClientCertificateId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

// gapFillAPIGatewayAccount discovers the account/region-level API Gateway
// settings singleton (CloudWatch role for execution logging, throttle
// settings) -- GetAccount takes no input.
func gapFillAPIGatewayAccount(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := agw.NewFromConfig(c.Cfg(region))
	out, err := cl.GetAccount(ctx, &agw.GetAccountInput{})
	if err != nil {
		return nil, nil
	}
	cfg := map[string]any{}
	if v := aws.ToString(out.CloudwatchRoleArn); v != "" {
		cfg["cloudwatch_role_arn"] = v
	}
	return []model.Resource{{
		Service: "apigateway", Type: "account", TFType: "aws_api_gateway_account",
		Region: region, ID: region, ImportID: region,
		Config: cfg,
	}}, nil
}
