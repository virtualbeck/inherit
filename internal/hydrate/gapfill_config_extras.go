package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	configservice "github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGapFiller(gapFillConfigRetention)
	registerGapFiller(gapFillConfigAggregateAuthorizations)
}

// gapFillConfigRetention discovers the region's Config configuration-item
// retention period -- a true account/region singleton (at most one per
// DescribeRetentionConfigurations' own doc comment), no ARN/tagging
// concept.
func gapFillConfigRetention(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := configservice.NewFromConfig(c.Cfg(region))
	out, err := cl.DescribeRetentionConfigurations(ctx, &configservice.DescribeRetentionConfigurationsInput{})
	if err != nil || len(out.RetentionConfigurations) == 0 {
		return nil, nil
	}
	rc := out.RetentionConfigurations[0]
	name := aws.ToString(rc.Name)
	if name == "" || rc.RetentionPeriodInDays == nil {
		return nil, nil
	}
	return []model.Resource{{
		Service: "config", Type: "retention-configuration", TFType: "aws_config_retention_configuration",
		Region: region, ID: name, ImportID: name,
		Config: map[string]any{"retention_period_in_days": int(*rc.RetentionPeriodInDays)},
	}}, nil
}

// gapFillConfigAggregateAuthorizations discovers cross-account/cross-region
// authorizations this account has granted to OTHER accounts' Config
// aggregators -- no ARN concept for the standalone tagging-API sweep to
// find (AggregationAuthorizationArn exists but isn't populated in an
// arnToTF-friendly way here), so gap-filled directly instead.
func gapFillConfigAggregateAuthorizations(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := configservice.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.DescribeAggregationAuthorizations(ctx, &configservice.DescribeAggregationAuthorizationsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, a := range page.AggregationAuthorizations {
			accountID := aws.ToString(a.AuthorizedAccountId)
			authRegion := aws.ToString(a.AuthorizedAwsRegion)
			if accountID == "" || authRegion == "" {
				continue
			}
			id := accountID + ":" + authRegion
			cfg := map[string]any{
				"account_id":            accountID,
				"authorized_aws_region": authRegion,
			}
			if arn := aws.ToString(a.AggregationAuthorizationArn); arn != "" {
				if lt, terr := cl.ListTagsForResource(ctx, &configservice.ListTagsForResourceInput{ResourceArn: &arn}); terr == nil && len(lt.Tags) > 0 {
					m := make(map[string]string, len(lt.Tags))
					for _, t := range lt.Tags {
						if k := aws.ToString(t.Key); k != "" {
							m[k] = aws.ToString(t.Value)
						}
					}
					cfg["tags"] = m
				}
			}
			out = append(out, model.Resource{
				Service: "config", Type: "aggregate-authorization", TFType: "aws_config_aggregate_authorization",
				Region: region, ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}
