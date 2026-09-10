package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerGlobalGapFiller(gapFillRoute53DelegationSets)
	registerGlobalGapFiller(gapFillRoute53QueryLogs)
}

// gapFillRoute53DelegationSets discovers reusable delegation sets: Route53
// is a global service, and delegation sets have no ARN or tagging support at
// all -- Read never even sets reference_name back, since it's
// create-only/ForceNew with no API to read it from -- so
// resourcegroupstaggingapi has no path to ever find them.
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
			// defensive: strip a possible "/delegationset/" prefix in case
			// the API ever returns the ID that way.
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

// gapFillRoute53QueryLogs discovers DNS query logging configs: no ARN or
// tagging attribute exists in the schema at all (only
// cloudwatch_log_group_arn/zone_id/arn/id, no tags), so
// resourcegroupstaggingapi has no path to find them either. Global service,
// same as delegation sets above.
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
