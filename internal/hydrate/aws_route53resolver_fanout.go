package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53rtypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_route53_resolver_rule", fanoutResolverRuleAssociations)
}

// fanoutResolverRuleAssociations expands a resolver rule into its VPC
// associations, each a separate top-level resource in the provider.
func fanoutResolverRuleAssociations(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := route53resolver.NewFromConfig(c.Cfg(parent.Region))
	var kids []model.Resource
	var token *string
	for {
		out, err := cl.ListResolverRuleAssociations(ctx, &route53resolver.ListResolverRuleAssociationsInput{
			Filters:   []r53rtypes.Filter{{Name: aws.String("ResolverRuleId"), Values: []string{parent.ID}}},
			NextToken: token,
		})
		if err != nil {
			return kids, err
		}
		for _, a := range out.ResolverRuleAssociations {
			id := aws.ToString(a.Id)
			if id == "" {
				continue
			}
			cfg := map[string]any{
				"resolver_rule_id": parent.ID,
				"vpc_id":           aws.ToString(a.VPCId),
			}
			if v := aws.ToString(a.Name); v != "" {
				cfg["name"] = v
			}
			kids = append(kids, model.Resource{
				Service: "route53resolver", Type: "resolver-rule-association", TFType: "aws_route53_resolver_rule_association",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	return kids, nil
}
