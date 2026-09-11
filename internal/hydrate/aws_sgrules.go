package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_security_group", fanoutSGRules)
}

// fanoutSGRules turns each rule of a security group into a standalone
// aws_vpc_security_group_(ingress|egress)_rule. AWS assigns each rule an
// sgr-* id, which is exactly what `terraform import` wants.
func fanoutSGRules(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	out, err := ec2.NewFromConfig(c.Cfg(parent.Region)).DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
		Filters: []ec2types.Filter{{Name: aws.String("group-id"), Values: []string{parent.ID}}},
	})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, r := range out.SecurityGroupRules {
		tfType := "aws_vpc_security_group_ingress_rule"
		if aws.ToBool(r.IsEgress) {
			tfType = "aws_vpc_security_group_egress_rule"
		}
		cfg := map[string]any{
			"security_group_id": parent.ID,
			"ip_protocol":       aws.ToString(r.IpProtocol),
		}
		if r.FromPort != nil && *r.FromPort >= 0 {
			cfg["from_port"] = *r.FromPort
		}
		if r.ToPort != nil && *r.ToPort >= 0 {
			cfg["to_port"] = *r.ToPort
		}
		switch {
		case aws.ToString(r.CidrIpv4) != "":
			cfg["cidr_ipv4"] = aws.ToString(r.CidrIpv4)
		case aws.ToString(r.CidrIpv6) != "":
			cfg["cidr_ipv6"] = aws.ToString(r.CidrIpv6)
		case r.ReferencedGroupInfo != nil && aws.ToString(r.ReferencedGroupInfo.GroupId) != "":
			cfg["referenced_security_group_id"] = aws.ToString(r.ReferencedGroupInfo.GroupId)
		case aws.ToString(r.PrefixListId) != "":
			cfg["prefix_list_id"] = aws.ToString(r.PrefixListId)
		}
		if d := aws.ToString(r.Description); d != "" {
			cfg["description"] = d
		}
		tags := map[string]string{}
		for _, t := range r.Tags {
			if k := aws.ToString(t.Key); k != "" && !strings.HasPrefix(k, "aws:") {
				tags[k] = aws.ToString(t.Value)
			}
		}
		if len(tags) > 0 {
			cfg["tags"] = tags
		}
		kids = append(kids, model.Resource{
			ARN:     aws.ToString(r.SecurityGroupRuleArn),
			Service: "ec2",
			Type:    "security-group-rule",
			TFType:  tfType,
			Region:  parent.Region,
			Account: parent.Account,
			ID:      aws.ToString(r.SecurityGroupRuleId),
			Tags:    tags,
			Config:  cfg,
		})
	}
	return kids, nil
}
