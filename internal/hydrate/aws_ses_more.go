package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGapFiller(gapFillSESReceiptRuleSets)
	registerFanout("aws_sesv2_email_identity", fanoutSESv2IdentityPolicies)
}

// v1-only receipt rule sets; no ARN or tags.
func gapFillSESReceiptRuleSets(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := ses.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.ListReceiptRuleSets(ctx, &ses.ListReceiptRuleSetsInput{NextToken: token})
		if err != nil {
			break
		}
		for _, rs := range page.RuleSets {
			name := aws.ToString(rs.Name)
			if name == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "ses", Type: "receipt-rule-set", TFType: "aws_ses_receipt_rule_set",
				Region: region, ID: name, ImportID: name,
				Config: map[string]any{"rule_set_name": name},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

func fanoutSESv2IdentityPolicies(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := sesv2.NewFromConfig(c.Cfg(parent.Region))
	identity := parent.ID
	out, err := cl.GetEmailIdentityPolicies(ctx, &sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: &identity})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for name, policy := range out.Policies {
		kids = append(kids, model.Resource{
			Service: "ses", Type: "identity-policy", TFType: "aws_sesv2_email_identity_policy",
			Region: parent.Region, Account: parent.Account,
			ID: identity + "|" + name, ImportID: identity + "|" + name,
			Config: map[string]any{
				"email_identity": identity, "policy_name": name, "policy": policy,
			},
		})
	}
	return kids, nil
}
