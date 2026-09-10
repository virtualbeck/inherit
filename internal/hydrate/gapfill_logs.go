package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerGapFiller(gapFillLogsResourcePolicies)
	registerGapFiller(gapFillLogsAccountPolicies)
}

// gapFillLogsResourcePolicies discovers CloudWatch Logs resource policies
// (used by other services -- EventBridge, VPC flow logs, etc. -- to grant
// PutLogEvents into a log group) -- an account/region-scoped list, no ARN
// or tagging concept.
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

// logsAccountPolicyTypes is the fixed enum DescribeAccountPolicies requires
// as input (it has no "list all types" mode) -- copied from the SDK's own
// PolicyType.Values() so it can't drift.
var logsAccountPolicyTypes = cwltypes.PolicyType("").Values()

// gapFillLogsAccountPolicies discovers account-wide CloudWatch Logs
// policies (data protection, subscription filter, field index, transformer,
// metric extraction) -- one DescribeAccountPolicies call per policy type,
// since the API has no way to list across all types at once.
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
