package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGlobalGapFiller(gapFillRoute53DelegationSets)
	registerGlobalGapFiller(gapFillRoute53QueryLogs)
}

// Global, untaggable, and reference_name is create-only.
func gapFillRoute53DelegationSets(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := route53.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	marker := (*string)(nil)
	for {
		page, err := cl.ListReusableDelegationSets(ctx, &route53.ListReusableDelegationSetsInput{Marker: marker})
		if err != nil {
			break
		}
		for _, ds := range page.DelegationSets {
			// strip a possible /delegationset/ prefix
			id := aws.ToString(ds.Id)
			if i := lastSlash(id); i >= 0 {
				id = id[i+1:]
			}
			out = append(out, model.Resource{
				Service: "route53", Type: "delegationset", TFType: "aws_route53_delegation_set",
				Region: region, ID: id, ImportID: id, Config: map[string]any{},
			})
		}
		if !page.IsTruncated {
			break
		}
		marker = page.NextMarker
	}

	return out, nil
}

func gapFillRoute53QueryLogs(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := route53.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	token := (*string)(nil)
	for {
		page, err := cl.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{NextToken: token})
		if err != nil {
			break
		}
		for _, q := range page.QueryLoggingConfigs {
			id := aws.ToString(q.Id)
			if id == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "route53", Type: "queryloggingconfig", TFType: "aws_route53_query_log",
				Region: region, ID: id, ImportID: id,
				Config: map[string]any{
					"cloudwatch_log_group_arn": aws.ToString(q.CloudWatchLogsLogGroupArn),
					"zone_id":                  aws.ToString(q.HostedZoneId),
				},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}

	return out, nil
}
