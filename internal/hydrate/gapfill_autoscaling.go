package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillAutoScalingGroups) }

// The Tagging API never returns ASGs.
func gapFillAutoScalingGroups(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := autoscaling.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	p := autoscaling.NewDescribeAutoScalingGroupsPaginator(cl, &autoscaling.DescribeAutoScalingGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, g := range page.AutoScalingGroups {
			name := aws.ToString(g.AutoScalingGroupName)
			if name == "" {
				continue
			}
			r := model.Resource{
				Service: "autoscaling", Type: "autoScalingGroup", TFType: "aws_autoscaling_group",
				ARN: aws.ToString(g.AutoScalingGroupARN), Region: region, ID: name,
			}
			if cfg, finalType, herr := hydrateRegistered(ctx, c, r); herr == nil && cfg != nil {
				r.TFType = finalType
				r.Config = cfg
				out = append(out, r)
			}
		}
	}
	return out, nil
}
