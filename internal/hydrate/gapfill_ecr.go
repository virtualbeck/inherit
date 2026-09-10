package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { registerGapFiller(gapFillECR) }

// gapFillECR discovers three account/region-scoped ECR registry settings:
// registry policy, replication configuration, and pull-through-cache rules.
// None of these have an ARN or support tagging: GetRegistryPolicy, for
// example, takes no input at all and always targets the current account's
// one registry (d.SetId(RegistryId) -- the account ID -- is the whole
// resource identity), so resourcegroupstaggingapi has no path to ever find
// them. ECR registries are genuinely per-region (unlike IAM's
// account-global scope), so this is a plain registerGapFiller, not global.
func gapFillECR(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := ecr.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	if pol, err := cl.GetRegistryPolicy(ctx, &ecr.GetRegistryPolicyInput{}); err == nil && pol.PolicyText != nil {
		id := aws.ToString(pol.RegistryId)
		out = append(out, model.Resource{
			Service: "ecr", Type: "registry-policy", TFType: "aws_ecr_registry_policy",
			Region: region, ID: id, ImportID: id,
			Config: map[string]any{"policy": aws.ToString(pol.PolicyText)},
		})
	}

	if reg, err := cl.DescribeRegistry(ctx, &ecr.DescribeRegistryInput{}); err == nil &&
		reg.ReplicationConfiguration != nil && len(reg.ReplicationConfiguration.Rules) > 0 {
		id := aws.ToString(reg.RegistryId)
		var rules []any
		for _, rule := range reg.ReplicationConfiguration.Rules {
			var dests []any
			for _, d := range rule.Destinations {
				dests = append(dests, map[string]any{
					"region":      aws.ToString(d.Region),
					"registry_id": aws.ToString(d.RegistryId),
				})
			}
			ruleCfg := map[string]any{"destination": dests}
			if len(rule.RepositoryFilters) > 0 {
				var filters []any
				for _, f := range rule.RepositoryFilters {
					filters = append(filters, map[string]any{
						"filter":      aws.ToString(f.Filter),
						"filter_type": string(f.FilterType),
					})
				}
				ruleCfg["repository_filter"] = filters
			}
			rules = append(rules, ruleCfg)
		}
		out = append(out, model.Resource{
			Service: "ecr", Type: "replication-configuration", TFType: "aws_ecr_replication_configuration",
			Region: region, ID: id, ImportID: id,
			Config: map[string]any{"replication_configuration": []any{map[string]any{"rule": rules}}},
		})
	}

	token := (*string)(nil)
	for {
		page, err := cl.DescribePullThroughCacheRules(ctx, &ecr.DescribePullThroughCacheRulesInput{NextToken: token})
		if err != nil {
			break
		}
		for _, r := range page.PullThroughCacheRules {
			addPullThroughCacheRule(&out, region, r)
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}

	return out, nil
}

func addPullThroughCacheRule(out *[]model.Resource, region string, r ecrtypes.PullThroughCacheRule) {
	prefix := aws.ToString(r.EcrRepositoryPrefix)
	cfg := map[string]any{
		"ecr_repository_prefix": prefix,
		"upstream_registry_url": aws.ToString(r.UpstreamRegistryUrl),
	}
	if v := aws.ToString(r.CredentialArn); v != "" {
		cfg["credential_arn"] = v
	}
	if v := aws.ToString(r.CustomRoleArn); v != "" {
		cfg["custom_role_arn"] = v
	}
	if v := aws.ToString(r.UpstreamRepositoryPrefix); v != "" {
		cfg["upstream_repository_prefix"] = v
	}
	*out = append(*out, model.Resource{
		Service: "ecr", Type: "pull-through-cache-rule", TFType: "aws_ecr_pull_through_cache_rule",
		Region: region, ID: prefix, ImportID: prefix,
		Config: cfg,
	})
}
