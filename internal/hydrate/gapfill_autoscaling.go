package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { registerGapFiller(gapFillAutoScalingGroups) }

// gapFillAutoScalingGroups discovers EC2 Auto Scaling groups directly:
// confirmed via AWS's own docs (Resource Groups Tagging API's "Services
// that support the Resource Groups Tagging API" list) and empirically
// against a real, tagged test group that resourcegroupstaggingapi
// (TagResources/UntagResources work, but GetResources, GetTagKeys, and
// GetTagValues aren't supported for this service and return an empty
// response -- unconditionally, regardless of tags. Not the same failure
// mode as the IAM/default-VPC gaps (both of those are specifically about
// UNTAGGED resources going unseen) -- this one drops every ASG, tagged or
// not, since the service never participates in that API at all.
//
// aws_autoscaling_group already has a real, working hydrator (hydrateASG)
// and fanout (fanoutASGExtras, for its scaling policies/scheduled actions/
// lifecycle hooks) -- both already correctly wired via the normal
// registry/fanoutRegistry lookups once a resource with TFType
// "aws_autoscaling_group" exists in the inventory. This only adds the
// missing discovery step, same shape as gapFillDefaultNetwork: enumerate
// via the service's own List/Describe call, then hydrate through
// hydrateRegistered (not a bare registry lookup) so retypeSentinel would
// still be honored if a future change ever needs it, even though this
// type doesn't retype today.
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
