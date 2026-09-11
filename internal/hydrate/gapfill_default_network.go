package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillDefaultNetwork) }

// gapFillDefaultNetwork discovers a region's default VPC and default
// security group directly: neither shows up via the normal tagging-API
// sweep, since nobody tags the VPC/security-group AWS auto-creates per
// region and resourcegroupstaggingapi:GetResources only ever returns
// tagged resources.
//
// Reuses the existing registered hydrators (via hydrateRegistered, not a
// bare registry lookup -- see its own doc for why) so hydration logic --
// including hydrateVPC's own retype to aws_default_vpc -- isn't
// duplicated; this only adds the discovery step. The default security
// group deliberately stays plain aws_security_group: unlike network ACLs
// (rejected as aws_network_acl when they're a VPC's default), the
// provider's own Read/Create for security groups doesn't reject a
// "default"-named group -- so no retype, and its existing SG-rule fanout
// (keyed on "aws_security_group") keeps working with no extra
// registration needed.
func gapFillDefaultNetwork(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := ec2.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	if vout, err := cl.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	}); err == nil {
		for _, v := range vout.Vpcs {
			id := aws.ToString(v.VpcId)
			tags := ec2TagMap(v.Tags)
			r := model.Resource{
				Service: "ec2", Type: "vpc", TFType: "aws_vpc",
				Region: region, ID: id, Tags: tags,
			}
			if cfg, finalType, herr := hydrateRegistered(ctx, c, r); herr == nil && cfg != nil {
				if len(tags) > 0 {
					cfg["tags"] = tags
				}
				r.TFType = finalType
				r.Config = cfg
				out = append(out, r)
			}
		}
	}

	if sout, err := cl.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{{Name: aws.String("group-name"), Values: []string{"default"}}},
	}); err == nil {
		for _, sg := range sout.SecurityGroups {
			id := aws.ToString(sg.GroupId)
			tags := ec2TagMap(sg.Tags)
			r := model.Resource{
				Service: "ec2", Type: "security-group", TFType: "aws_security_group",
				ARN: aws.ToString(sg.SecurityGroupArn), Region: region, ID: id, Tags: tags,
			}
			if cfg, finalType, herr := hydrateRegistered(ctx, c, r); herr == nil && cfg != nil {
				if len(tags) > 0 {
					cfg["tags"] = tags
				}
				r.TFType = finalType
				r.Config = cfg
				out = append(out, r)
			}
		}
	}

	return out, nil
}

// ec2TagMap converts EC2's []Tag{Key,Value} into a plain map, the shape
// model.Resource.Tags and cfg["tags"] both expect. "aws:"-prefixed
// reserved tags are already stripped at discovery time for the normal
// tagging-API sweep (internal/discover); this mirrors that for a
// gap-filled resource, which bypasses that path entirely.
func ec2TagMap(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if k := aws.ToString(t.Key); k != "" && !hasPrefix(k, "aws:") {
			m[k] = aws.ToString(t.Value)
		}
	}
	return m
}
