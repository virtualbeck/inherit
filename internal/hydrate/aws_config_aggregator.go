package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { register("aws_config_configuration_aggregator", hydrateConfigAggregator) }

// hydrateConfigAggregator is hand-built rather than Generic(): the SDK's
// AccountAggregationSource/OrganizationAggregationSource use AwsRegions/
// AllAwsRegions, which don't snake-case to the schema's regions/all_regions
// (an attribute-name mismatch within an otherwise-fine nested block, not the
// whole-block-drop failure mode -- Generic() would just silently omit those
// two fields from each block instead).
func hydrateConfigAggregator(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := configservice.NewFromConfig(c.Cfg(r.Region)).DescribeConfigurationAggregators(ctx, &configservice.DescribeConfigurationAggregatorsInput{
		ConfigurationAggregatorNames: []string{name},
	})
	if err != nil || len(out.ConfigurationAggregators) == 0 {
		return nil, err
	}
	a := out.ConfigurationAggregators[0]
	cfg := map[string]any{"name": aws.ToString(a.ConfigurationAggregatorName)}
	if len(a.AccountAggregationSources) > 0 {
		cfg["account_aggregation_source"] = []any{accountAggregationSourceCfg(a.AccountAggregationSources[0])}
	}
	if a.OrganizationAggregationSource != nil {
		cfg["organization_aggregation_source"] = []any{orgAggregationSourceCfg(*a.OrganizationAggregationSource)}
	}
	return cfg, nil
}

func accountAggregationSourceCfg(s cstypes.AccountAggregationSource) map[string]any {
	m := map[string]any{"account_ids": toAny(s.AccountIds), "all_regions": s.AllAwsRegions}
	if len(s.AwsRegions) > 0 {
		m["regions"] = toAny(s.AwsRegions)
	}
	return m
}

func orgAggregationSourceCfg(s cstypes.OrganizationAggregationSource) map[string]any {
	m := map[string]any{"role_arn": aws.ToString(s.RoleArn), "all_regions": s.AllAwsRegions}
	if len(s.AwsRegions) > 0 {
		m["regions"] = toAny(s.AwsRegions)
	}
	return m
}
