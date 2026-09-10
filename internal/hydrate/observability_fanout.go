package hydrate

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_cloudwatch_log_group", fanoutLogFilters)
}

func fanoutLogFilters(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := cwl.NewFromConfig(c.Cfg(parent.Region))
	grp := parent.ID
	var kids []model.Resource

	if mf, err := cl.DescribeMetricFilters(ctx, &cwl.DescribeMetricFiltersInput{LogGroupName: &grp}); err == nil {
		for _, f := range mf.MetricFilters {
			cfg := map[string]any{
				"name":           aws.ToString(f.FilterName),
				"log_group_name": grp,
				"pattern":        aws.ToString(f.FilterPattern),
			}
			for _, t := range f.MetricTransformations {
				mt := map[string]any{
					"name":      aws.ToString(t.MetricName),
					"namespace": aws.ToString(t.MetricNamespace),
					"value":     aws.ToString(t.MetricValue),
				}
				if t.DefaultValue != nil {
					mt["default_value"] = strconv.FormatFloat(*t.DefaultValue, 'f', -1, 64)
				}
				if len(t.Dimensions) > 0 {
					dims := map[string]any{}
					for dk, dv := range t.Dimensions {
						dims[dk] = dv
					}
					mt["dimensions"] = dims
				}
				if u := string(t.Unit); u != "" {
					mt["unit"] = u
				}
				cfg["metric_transformation"] = mt
			}
			kids = append(kids, model.Resource{
				Service: "logs", Type: "metric-filter", TFType: "aws_cloudwatch_log_metric_filter",
				Region: parent.Region, Account: parent.Account,
				ID: aws.ToString(f.FilterName),
				// the provider imports by "log-group-name:filter-name",
				// not the bare filter name.
				ImportID: grp + ":" + aws.ToString(f.FilterName),
				Config:   cfg,
			})
		}
	}

	if sf, err := cl.DescribeSubscriptionFilters(ctx, &cwl.DescribeSubscriptionFiltersInput{LogGroupName: &grp}); err == nil {
		for _, f := range sf.SubscriptionFilters {
			cfg := map[string]any{
				"name":            aws.ToString(f.FilterName),
				"log_group_name":  grp,
				"filter_pattern":  aws.ToString(f.FilterPattern),
				"destination_arn": aws.ToString(f.DestinationArn),
			}
			if v := aws.ToString(f.RoleArn); v != "" {
				cfg["role_arn"] = v
			}
			kids = append(kids, model.Resource{
				Service: "logs", Type: "subscription-filter", TFType: "aws_cloudwatch_log_subscription_filter",
				Region: parent.Region, Account: parent.Account,
				ID:     grp + "|" + aws.ToString(f.FilterName),
				Config: cfg,
			})
		}
	}
	return kids, nil
}
