package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillLogsDestinations) }

// gapFillLogsDestinations discovers CloudWatch Logs subscription
// destinations (cross-account log shipping targets, e.g. into a Kinesis
// stream) and, for any that has one, its access policy as a separate
// resource -- the schema models these as two distinct types even though
// DescribeDestinations returns the policy right alongside the destination
// itself.
func gapFillLogsDestinations(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := cwl.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.DescribeDestinations(ctx, &cwl.DescribeDestinationsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, d := range page.Destinations {
			name := aws.ToString(d.DestinationName)
			if name == "" {
				continue
			}
			cfg := map[string]any{
				"name":       name,
				"role_arn":   aws.ToString(d.RoleArn),
				"target_arn": aws.ToString(d.TargetArn),
			}
			var tags map[string]string
			if arn := aws.ToString(d.Arn); arn != "" {
				if lt, terr := cl.ListTagsForResource(ctx, &cwl.ListTagsForResourceInput{ResourceArn: &arn}); terr == nil && len(lt.Tags) > 0 {
					tags = lt.Tags
					cfg["tags"] = tags
				}
			}
			out = append(out, model.Resource{
				Service: "logs", Type: "destination", TFType: "aws_cloudwatch_log_destination",
				Region: region, ID: name, ImportID: name,
				Tags:   tags,
				Config: cfg,
			})

			if policy := aws.ToString(d.AccessPolicy); policy != "" {
				out = append(out, model.Resource{
					Service: "logs", Type: "destination-policy", TFType: "aws_cloudwatch_log_destination_policy",
					Region: region, ID: name, ImportID: name,
					Config: map[string]any{
						"destination_name": name,
						"access_policy":    policy,
					},
				})
			}
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}
