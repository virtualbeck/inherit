package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_opensearch_domain", fanoutOpenSearchExtras)
}

// fanoutOpenSearchExtras expands a domain into its access-policy resource
// (modeled separately from the domain by the provider even though
// DescribeDomain already returns AccessPolicies alongside everything else)
// and any outbound VPC endpoints associated with it.
func fanoutOpenSearchExtras(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := opensearch.NewFromConfig(c.Cfg(parent.Region))
	name := parent.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	var kids []model.Resource

	if out, err := cl.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &name}); err == nil && out.DomainStatus != nil {
		if policy := aws.ToString(out.DomainStatus.AccessPolicies); policy != "" {
			kids = append(kids, model.Resource{
				Service: "es", Type: "domain-policy", TFType: "aws_opensearch_domain_policy",
				Region: parent.Region, Account: parent.Account,
				ID: name, ImportID: name,
				Config: map[string]any{"domain_name": name, "access_policies": policy},
			})
		}

		domainArn := aws.ToString(out.DomainStatus.ARN)
		if domainArn != "" {
			token := (*string)(nil)
			var epIDs []string
			for {
				page, err := cl.ListVpcEndpointsForDomain(ctx, &opensearch.ListVpcEndpointsForDomainInput{DomainName: &name, NextToken: token})
				if err != nil {
					break
				}
				for _, s := range page.VpcEndpointSummaryList {
					if id := aws.ToString(s.VpcEndpointId); id != "" {
						epIDs = append(epIDs, id)
					}
				}
				if aws.ToString(page.NextToken) == "" {
					break
				}
				token = page.NextToken
			}
			if len(epIDs) > 0 {
				if desc, err := cl.DescribeVpcEndpoints(ctx, &opensearch.DescribeVpcEndpointsInput{VpcEndpointIds: epIDs}); err == nil {
					for _, ep := range desc.VpcEndpoints {
						id := aws.ToString(ep.VpcEndpointId)
						if id == "" || ep.VpcOptions == nil {
							continue
						}
						vo := map[string]any{}
						if len(ep.VpcOptions.SubnetIds) > 0 {
							vo["subnet_ids"] = toAny(ep.VpcOptions.SubnetIds)
						}
						if len(ep.VpcOptions.SecurityGroupIds) > 0 {
							vo["security_group_ids"] = toAny(ep.VpcOptions.SecurityGroupIds)
						}
						kids = append(kids, model.Resource{
							Service: "es", Type: "vpc-endpoint", TFType: "aws_opensearch_vpc_endpoint",
							Region: parent.Region, Account: parent.Account,
							ID: id, ImportID: id,
							Config: map[string]any{
								"domain_arn":  domainArn,
								"vpc_options": []any{vo},
							},
						})
					}
				}
			}
		}
	}

	return kids, nil
}
