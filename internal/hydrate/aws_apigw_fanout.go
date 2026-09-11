package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	agw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_api_gateway_rest_api", fanoutRestAPI)
}

// fanoutRestAPI expands a REST API into its resource / method / integration
// tree plus authorizers, models, validators, deployments, stages and any
// customized gateway responses. Each child imports with a compound id.
func fanoutRestAPI(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := agw.NewFromConfig(c.Cfg(parent.Region))
	api := parent.ID
	var kids []model.Resource

	mk := func(tfType, subType, wireID, importID string, cfg map[string]any) {
		cfg["rest_api_id"] = api
		kids = append(kids, model.Resource{
			Service: "apigateway", Type: subType, TFType: tfType,
			Region: parent.Region, Account: parent.Account,
			ID: wireID, ImportID: importID, Config: cfg,
		})
	}

	// --- resource / method / integration tree ---------------------------
	p := agw.NewGetResourcesPaginator(cl, &agw.GetResourcesInput{
		RestApiId: &api, Embed: []string{"methods"}, Limit: aws.Int32(500),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return kids, err
		}
		for _, res := range page.Items {
			rid := aws.ToString(res.Id)
			if aws.ToString(res.PathPart) != "" { // the root resource belongs to the rest_api
				mk("aws_api_gateway_resource", "resource", rid, api+"/"+rid, map[string]any{
					"parent_id": aws.ToString(res.ParentId),
					"path_part": aws.ToString(res.PathPart),
				})
			}
			for httpMethod, m := range res.ResourceMethods {
				base := api + "/" + rid + "/" + httpMethod
				mcfg := map[string]any{
					"resource_id":   rid,
					"http_method":   httpMethod,
					"authorization": orDefault(aws.ToString(m.AuthorizationType), "NONE"),
				}
				if aws.ToBool(m.ApiKeyRequired) {
					mcfg["api_key_required"] = true
				}
				if v := aws.ToString(m.AuthorizerId); v != "" {
					mcfg["authorizer_id"] = v
				}
				if v := aws.ToString(m.RequestValidatorId); v != "" {
					mcfg["request_validator_id"] = v
				}
				if len(m.RequestParameters) > 0 {
					mcfg["request_parameters"] = boolMap(m.RequestParameters)
				}
				if len(m.RequestModels) > 0 {
					mcfg["request_models"] = strMap(m.RequestModels)
				}
				mk("aws_api_gateway_method", "method", base, base, mcfg)

				if in := m.MethodIntegration; in != nil {
					icfg := map[string]any{
						"resource_id": rid,
						"http_method": httpMethod,
						"type":        string(in.Type),
					}
					if v := aws.ToString(in.HttpMethod); v != "" {
						icfg["integration_http_method"] = v
					}
					if v := aws.ToString(in.Uri); v != "" {
						icfg["uri"] = v
					}
					if v := string(in.ConnectionType); v != "" && v != "INTERNET" {
						icfg["connection_type"] = v
					}
					if v := aws.ToString(in.ConnectionId); v != "" {
						icfg["connection_id"] = v
					}
					if v := aws.ToString(in.Credentials); v != "" {
						icfg["credentials"] = v
					}
					if v := aws.ToString(in.PassthroughBehavior); v != "" {
						icfg["passthrough_behavior"] = v
					}
					if v := string(in.ContentHandling); v != "" {
						icfg["content_handling"] = v
					}
					if in.TimeoutInMillis != 0 {
						icfg["timeout_milliseconds"] = in.TimeoutInMillis
					}
					if v := aws.ToString(in.CacheNamespace); v != "" {
						icfg["cache_namespace"] = v
					}
					if len(in.CacheKeyParameters) > 0 {
						icfg["cache_key_parameters"] = toAny(in.CacheKeyParameters)
					}
					if len(in.RequestParameters) > 0 {
						icfg["request_parameters"] = strMap(in.RequestParameters)
					}
					if len(in.RequestTemplates) > 0 {
						icfg["request_templates"] = strMap(in.RequestTemplates)
					}
					mk("aws_api_gateway_integration", "integration", base, base, icfg)

					for sc, ir := range in.IntegrationResponses {
						ircfg := map[string]any{
							"resource_id": rid, "http_method": httpMethod, "status_code": sc,
						}
						if v := aws.ToString(ir.SelectionPattern); v != "" {
							ircfg["selection_pattern"] = v
						}
						if v := string(ir.ContentHandling); v != "" {
							ircfg["content_handling"] = v
						}
						if len(ir.ResponseTemplates) > 0 {
							ircfg["response_templates"] = strMap(ir.ResponseTemplates)
						}
						if len(ir.ResponseParameters) > 0 {
							ircfg["response_parameters"] = strMap(ir.ResponseParameters)
						}
						mk("aws_api_gateway_integration_response", "integration-response",
							base+"/"+sc, base+"/"+sc, ircfg)
					}
				}

				for sc, mr := range m.MethodResponses {
					mrcfg := map[string]any{
						"resource_id": rid, "http_method": httpMethod, "status_code": sc,
					}
					if len(mr.ResponseModels) > 0 {
						mrcfg["response_models"] = strMap(mr.ResponseModels)
					}
					if len(mr.ResponseParameters) > 0 {
						mrcfg["response_parameters"] = boolMap(mr.ResponseParameters)
					}
					mk("aws_api_gateway_method_response", "method-response",
						base+"/"+sc, base+"/"+sc, mrcfg)
				}
			}
		}
	}

	// --- authorizers ---------------------------------------------------
	if az, err := cl.GetAuthorizers(ctx, &agw.GetAuthorizersInput{RestApiId: &api}); err == nil {
		for _, a := range az.Items {
			id := aws.ToString(a.Id)
			cfg := map[string]any{
				"name": aws.ToString(a.Name),
				"type": string(a.Type),
			}
			if v := aws.ToString(a.AuthorizerUri); v != "" {
				cfg["authorizer_uri"] = v
			}
			if v := aws.ToString(a.AuthorizerCredentials); v != "" {
				cfg["authorizer_credentials"] = v
			}
			if v := aws.ToString(a.IdentitySource); v != "" {
				cfg["identity_source"] = v
			}
			if v := aws.ToString(a.IdentityValidationExpression); v != "" {
				cfg["identity_validation_expression"] = v
			}
			if len(a.ProviderARNs) > 0 {
				cfg["provider_arns"] = toAny(a.ProviderARNs)
			}
			if a.AuthorizerResultTtlInSeconds != nil {
				cfg["authorizer_result_ttl_in_seconds"] = *a.AuthorizerResultTtlInSeconds
			}
			mk("aws_api_gateway_authorizer", "authorizer", id, api+"/"+id, cfg)
		}
	}

	// --- request validators ------------------------------------------
	if rv, err := cl.GetRequestValidators(ctx, &agw.GetRequestValidatorsInput{RestApiId: &api}); err == nil {
		for _, v := range rv.Items {
			id := aws.ToString(v.Id)
			mk("aws_api_gateway_request_validator", "request-validator", id, api+"/"+id, map[string]any{
				"name":                        aws.ToString(v.Name),
				"validate_request_body":       v.ValidateRequestBody,
				"validate_request_parameters": v.ValidateRequestParameters,
			})
		}
	}

	// --- models ------------------------------------------------------
	if md, err := cl.GetModels(ctx, &agw.GetModelsInput{RestApiId: &api}); err == nil {
		for _, m := range md.Items {
			name := aws.ToString(m.Name)
			cfg := map[string]any{
				"name":         name,
				"content_type": aws.ToString(m.ContentType),
			}
			if v := aws.ToString(m.Schema); v != "" {
				cfg["schema"] = v
			}
			if v := aws.ToString(m.Description); v != "" {
				cfg["description"] = v
			}
			mk("aws_api_gateway_model", "model", name, api+"/"+name, cfg)
		}
	}

	// --- deployments -----------------------------------------------
	if dp, err := cl.GetDeployments(ctx, &agw.GetDeploymentsInput{RestApiId: &api}); err == nil {
		for _, d := range dp.Items {
			id := aws.ToString(d.Id)
			cfg := map[string]any{}
			if v := aws.ToString(d.Description); v != "" {
				cfg["description"] = v
			}
			mk("aws_api_gateway_deployment", "deployment", id, api+"/"+id, cfg)
		}
	}

	// --- stages --------------------------------------------------
	if st, err := cl.GetStages(ctx, &agw.GetStagesInput{RestApiId: &api}); err == nil {
		for _, s := range st.Item {
			name := aws.ToString(s.StageName)
			cfg := map[string]any{
				"stage_name":    name,
				"deployment_id": aws.ToString(s.DeploymentId),
			}
			if v := aws.ToString(s.Description); v != "" {
				cfg["description"] = v
			}
			if s.CacheClusterEnabled {
				cfg["cache_cluster_enabled"] = true
				if v := string(s.CacheClusterSize); v != "" {
					cfg["cache_cluster_size"] = v
				}
			}
			if s.TracingEnabled {
				cfg["xray_tracing_enabled"] = true
			}
			if v := aws.ToString(s.DocumentationVersion); v != "" {
				cfg["documentation_version"] = v
			}
			if len(s.Variables) > 0 {
				cfg["variables"] = strMap(s.Variables)
			}
			if len(s.Tags) > 0 {
				cfg["tags"] = s.Tags
			}
			mk("aws_api_gateway_stage", "stage", api+"/"+name, api+"/"+name, cfg)
		}
	}

	// --- customized gateway responses --------------------------
	if gr, err := cl.GetGatewayResponses(ctx, &agw.GetGatewayResponsesInput{RestApiId: &api}); err == nil {
		for _, g := range gr.Items {
			if g.DefaultResponse { // only the ones actually customized
				continue
			}
			rt := string(g.ResponseType)
			cfg := map[string]any{"response_type": rt}
			if v := aws.ToString(g.StatusCode); v != "" {
				cfg["status_code"] = v
			}
			if len(g.ResponseTemplates) > 0 {
				cfg["response_templates"] = strMap(g.ResponseTemplates)
			}
			if len(g.ResponseParameters) > 0 {
				cfg["response_parameters"] = strMap(g.ResponseParameters)
			}
			mk("aws_api_gateway_gateway_response", "gateway-response", api+"/"+rt, api+"/"+rt, cfg)
		}
	}

	return kids, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func strMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func boolMap(m map[string]bool) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
