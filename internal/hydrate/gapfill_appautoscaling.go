package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	aas "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillAppAutoscaling) }

// application auto scaling namespaces worth probing: every namespace the SDK
// knows about (aastypes.ServiceNamespace.Values()). DescribeScalableTargets/
// DescribeScalingPolicies are plain read calls even for "custom-resource" --
// nothing about probing it needs a linked feature, only *registering* a new
// custom-resource scalable target does (a write operation this tool never
// performs anyway). A namespace the account doesn't use, or lacks permission
// for, already errors out cleanly per-page below and just gets skipped.
var aasNamespaces = aastypes.ServiceNamespace("").Values()

func gapFillAppAutoscaling(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := aas.NewFromConfig(c.Cfg(region))
	acct := ""
	var out []model.Resource

	for _, ns := range aasNamespaces {
		tp := aas.NewDescribeScalableTargetsPaginator(cl, &aas.DescribeScalableTargetsInput{ServiceNamespace: ns})
		for tp.HasMorePages() {
			page, err := tp.NextPage(ctx)
			if err != nil {
				break // namespace not enabled / not permitted; move on
			}
			for _, t := range page.ScalableTargets {
				sn := string(t.ServiceNamespace)
				rid := aws.ToString(t.ResourceId)
				dim := string(t.ScalableDimension)
				cfg := map[string]any{
					"service_namespace":  sn,
					"resource_id":        rid,
					"scalable_dimension": dim,
				}
				if t.MinCapacity != nil {
					cfg["min_capacity"] = *t.MinCapacity
				}
				if t.MaxCapacity != nil {
					cfg["max_capacity"] = *t.MaxCapacity
				}
				if v := aws.ToString(t.ScalableTargetARN); v != "" {
					if tags, terr := cl.ListTagsForResource(ctx, &aas.ListTagsForResourceInput{ResourceARN: &v}); terr == nil && len(tags.Tags) > 0 {
						cfg["tags"] = tags.Tags
					}
				}
				id := sn + "/" + rid + "/" + dim
				out = append(out, model.Resource{
					Service: "application-autoscaling", Type: "scalable-target",
					TFType: "aws_appautoscaling_target", Region: region, Account: acct,
					ID: id, ImportID: id, Config: cfg,
				})
			}
		}

		pp := aas.NewDescribeScalingPoliciesPaginator(cl, &aas.DescribeScalingPoliciesInput{ServiceNamespace: ns})
		for pp.HasMorePages() {
			page, err := pp.NextPage(ctx)
			if err != nil {
				break
			}
			for _, p := range page.ScalingPolicies {
				sn := string(p.ServiceNamespace)
				rid := aws.ToString(p.ResourceId)
				dim := string(p.ScalableDimension)
				name := aws.ToString(p.PolicyName)
				cfg := map[string]any{
					"name":               name,
					"service_namespace":  sn,
					"resource_id":        rid,
					"scalable_dimension": dim,
					"policy_type":        string(p.PolicyType),
				}
				if tt := p.TargetTrackingScalingPolicyConfiguration; tt != nil {
					cfg["target_tracking_scaling_policy_configuration"] = aasTargetTracking(tt)
				}
				if ss := p.StepScalingPolicyConfiguration; ss != nil {
					cfg["step_scaling_policy_configuration"] = aasStepScaling(ss)
				}
				id := sn + "/" + rid + "/" + dim + "/" + name
				out = append(out, model.Resource{
					Service: "application-autoscaling", Type: "scaling-policy",
					TFType: "aws_appautoscaling_policy", Region: region, Account: acct,
					ID: id, ImportID: id, Config: cfg,
				})
			}
		}
	}
	return out, nil
}

func aasTargetTracking(t *aastypes.TargetTrackingScalingPolicyConfiguration) map[string]any {
	m := map[string]any{}
	if t.TargetValue != nil {
		m["target_value"] = *t.TargetValue
	}
	if t.DisableScaleIn != nil && *t.DisableScaleIn {
		m["disable_scale_in"] = true
	}
	if t.ScaleInCooldown != nil {
		m["scale_in_cooldown"] = *t.ScaleInCooldown
	}
	if t.ScaleOutCooldown != nil {
		m["scale_out_cooldown"] = *t.ScaleOutCooldown
	}
	if p := t.PredefinedMetricSpecification; p != nil {
		pm := map[string]any{"predefined_metric_type": string(p.PredefinedMetricType)}
		if v := aws.ToString(p.ResourceLabel); v != "" {
			pm["resource_label"] = v
		}
		m["predefined_metric_specification"] = pm
	}
	if cm := t.CustomizedMetricSpecification; cm != nil {
		c := map[string]any{}
		if v := aws.ToString(cm.MetricName); v != "" {
			c["metric_name"] = v
		}
		if v := aws.ToString(cm.Namespace); v != "" {
			c["namespace"] = v
		}
		if v := string(cm.Statistic); v != "" {
			c["statistic"] = v
		}
		if v := aws.ToString(cm.Unit); v != "" {
			c["unit"] = v
		}
		var dims []any
		for _, d := range cm.Dimensions {
			dims = append(dims, map[string]any{
				"name": aws.ToString(d.Name), "value": aws.ToString(d.Value),
			})
		}
		if len(dims) > 0 {
			c["dimensions"] = dims
		}
		if len(c) > 0 {
			m["customized_metric_specification"] = c
		}
	}
	return m
}

func aasStepScaling(s *aastypes.StepScalingPolicyConfiguration) map[string]any {
	m := map[string]any{}
	if v := string(s.AdjustmentType); v != "" {
		m["adjustment_type"] = v
	}
	if s.Cooldown != nil {
		m["cooldown"] = *s.Cooldown
	}
	if v := string(s.MetricAggregationType); v != "" {
		m["metric_aggregation_type"] = v
	}
	if s.MinAdjustmentMagnitude != nil {
		m["min_adjustment_magnitude"] = *s.MinAdjustmentMagnitude
	}
	var steps []any
	for _, st := range s.StepAdjustments {
		sa := map[string]any{}
		if st.ScalingAdjustment != nil {
			sa["scaling_adjustment"] = *st.ScalingAdjustment
		}
		if st.MetricIntervalLowerBound != nil {
			sa["metric_interval_lower_bound"] = *st.MetricIntervalLowerBound
		}
		if st.MetricIntervalUpperBound != nil {
			sa["metric_interval_upper_bound"] = *st.MetricIntervalUpperBound
		}
		steps = append(steps, sa)
	}
	if len(steps) > 0 {
		m["step_adjustment"] = steps
	}
	return m
}
