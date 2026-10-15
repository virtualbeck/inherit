package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGapFiller(gapFillLogsResourcePolicies)
	registerGapFiller(gapFillLogsAccountPolicies)
}

func gapFillLogsResourcePolicies(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := cwl.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.DescribeResourcePolicies(ctx, &cwl.DescribeResourcePoliciesInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, p := range page.ResourcePolicies {
			name := aws.ToString(p.PolicyName)
			if name == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "logs", Type: "resource-policy", TFType: "aws_cloudwatch_log_resource_policy",
				Region: region, ID: name, ImportID: name,
				Config: map[string]any{
					"policy_name":     name,
					"policy_document": aws.ToString(p.PolicyDocument),
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

// Required input; no list-all mode.
var logsAccountPolicyTypes = cwltypes.PolicyType("").Values()

// One call per policy type.
func gapFillLogsAccountPolicies(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := cwl.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	for _, pt := range logsAccountPolicyTypes {
		page, err := cl.DescribeAccountPolicies(ctx, &cwl.DescribeAccountPoliciesInput{PolicyType: pt})
		if err != nil {
			continue
		}
		for _, p := range page.AccountPolicies {
			name := aws.ToString(p.PolicyName)
			if name == "" {
				continue
			}
			cfg := map[string]any{
				"policy_name":     name,
				"policy_type":     string(p.PolicyType),
				"policy_document": aws.ToString(p.PolicyDocument),
			}
			if v := string(p.Scope); v != "" {
				cfg["scope"] = v
			}
			if v := aws.ToString(p.SelectionCriteria); v != "" {
				cfg["selection_criteria"] = v
			}
			out = append(out, model.Resource{
				Service: "logs", Type: "account-policy", TFType: "aws_cloudwatch_log_account_policy",
				Region: region, ID: name, ImportID: name + ":" + string(p.PolicyType),
				Config: cfg,
			})
		}
	}
	return out, nil
}
