package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_apigatewayv2_api", fanoutAPIGWv2)
}

// fanoutAPIGWv2 expands an HTTP/WebSocket API into its stages, routes and
// integrations as standalone resources.
func fanoutAPIGWv2(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := apigatewayv2.NewFromConfig(c.Cfg(parent.Region))
	api := parent.ID
	var kids []model.Resource

	if st, err := cl.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: &api}); err == nil {
		for _, s := range st.Items {
			cfg := map[string]any{
				"api_id": api,
				"name":   aws.ToString(s.StageName),
			}
			if aws.ToBool(s.AutoDeploy) {
				cfg["auto_deploy"] = true
			}
			if v := aws.ToString(s.Description); v != "" {
				cfg["description"] = v
			}
			if len(s.Tags) > 0 {
				cfg["tags"] = s.Tags
			}
			kids = append(kids, model.Resource{
				Service: "apigateway", Type: "stage", TFType: "aws_apigatewayv2_stage",
				Region: parent.Region, Account: parent.Account,
				ID:     api + "/" + aws.ToString(s.StageName),
				Tags:   s.Tags,
				Config: cfg,
			})
		}
	}

	if rt, err := cl.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: &api}); err == nil {
		for _, r := range rt.Items {
			cfg := map[string]any{
				"api_id":    api,
				"route_key": aws.ToString(r.RouteKey),
			}
			if v := aws.ToString(r.Target); v != "" {
				cfg["target"] = v
			}
			if v := string(r.AuthorizationType); v != "" && v != "NONE" {
				cfg["authorization_type"] = v
			}
			kids = append(kids, model.Resource{
				Service: "apigateway", Type: "route", TFType: "aws_apigatewayv2_route",
				Region: parent.Region, Account: parent.Account,
				ID:     api + "/" + aws.ToString(r.RouteId),
				Config: cfg,
			})
		}
	}

	if ig, err := cl.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{ApiId: &api}); err == nil {
		for _, in := range ig.Items {
			cfg := map[string]any{
				"api_id":           api,
				"integration_type": string(in.IntegrationType),
			}
			if v := aws.ToString(in.IntegrationUri); v != "" {
				cfg["integration_uri"] = v
			}
			if v := aws.ToString(in.IntegrationMethod); v != "" {
				cfg["integration_method"] = v
			}
			if v := aws.ToString(in.PayloadFormatVersion); v != "" {
				cfg["payload_format_version"] = v
			}
			if v := aws.ToString(in.ConnectionId); v != "" {
				cfg["connection_id"] = v
			}
			kids = append(kids, model.Resource{
				Service: "apigateway", Type: "integration", TFType: "aws_apigatewayv2_integration",
				Region: parent.Region, Account: parent.Account,
				ID:     api + "/" + aws.ToString(in.IntegrationId),
				Config: cfg,
			})
		}
	}

	return kids, nil
}
