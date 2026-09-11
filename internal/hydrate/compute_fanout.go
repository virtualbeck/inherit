package hydrate

import (
	"context"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_autoscaling_group", fanoutASGExtras)
}

// fanoutASGExtras emits scaling policies, scheduled actions and lifecycle hooks
// of an auto scaling group.
func fanoutASGExtras(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := autoscaling.NewFromConfig(c.Cfg(parent.Region))
	asg := parent.ID
	var kids []model.Resource

	if pol, err := cl.DescribePolicies(ctx, &autoscaling.DescribePoliciesInput{AutoScalingGroupName: &asg}); err == nil {
		for _, p := range pol.ScalingPolicies {
			name := aws.ToString(p.PolicyName)
			cfg := map[string]any{
				"name":                   name,
				"autoscaling_group_name": asg,
				"policy_type":            aws.ToString(p.PolicyType),
			}
			if v := aws.ToString(p.AdjustmentType); v != "" {
				cfg["adjustment_type"] = v
			}
			if p.ScalingAdjustment != nil {
				cfg["scaling_adjustment"] = *p.ScalingAdjustment
			}
			if p.Cooldown != nil {
				cfg["cooldown"] = *p.Cooldown
			}
			if p.EstimatedInstanceWarmup != nil {
				cfg["estimated_instance_warmup"] = *p.EstimatedInstanceWarmup
			}
			if v := aws.ToString(p.MetricAggregationType); v != "" {
				cfg["metric_aggregation_type"] = v
			}
			if p.MinAdjustmentMagnitude != nil {
				cfg["min_adjustment_magnitude"] = *p.MinAdjustmentMagnitude
			}
			// TargetTrackingConfiguration/StepAdjustments are the actual scaling
			// rule for a "TargetTrackingScaling"/"StepScaling" policy -- without
			// it, config for a target-tracking policy (the common case in real
			// accounts, e.g. CPU-utilization based scaling) is missing its one
			// Required block entirely. PredictiveScalingConfiguration (a third,
			// rarer policy type) is not handled here.
			if tt := p.TargetTrackingConfiguration; tt != nil {
				ttm := map[string]any{}
				if tt.TargetValue != nil {
					ttm["target_value"] = *tt.TargetValue
				}
				if tt.DisableScaleIn != nil {
					ttm["disable_scale_in"] = *tt.DisableScaleIn
				}
				if pm := tt.PredefinedMetricSpecification; pm != nil {
					pms := map[string]any{"predefined_metric_type": string(pm.PredefinedMetricType)}
					if v := aws.ToString(pm.ResourceLabel); v != "" {
						pms["resource_label"] = v
					}
					ttm["predefined_metric_specification"] = []any{pms}
				}
				if cm := tt.CustomizedMetricSpecification; cm != nil {
					cms := map[string]any{}
					if v := aws.ToString(cm.MetricName); v != "" {
						cms["metric_name"] = v
					}
					if v := aws.ToString(cm.Namespace); v != "" {
						cms["namespace"] = v
					}
					if v := string(cm.Statistic); v != "" {
						cms["statistic"] = v
					}
					if v := aws.ToString(cm.Unit); v != "" {
						cms["unit"] = v
					}
					if cm.Period != nil {
						cms["period"] = *cm.Period
					}
					var dims []any
					for _, d := range cm.Dimensions {
						dims = append(dims, map[string]any{"name": aws.ToString(d.Name), "value": aws.ToString(d.Value)})
					}
					if len(dims) > 0 {
						cms["metric_dimension"] = dims
					}
					ttm["customized_metric_specification"] = []any{cms}
				}
				cfg["target_tracking_configuration"] = []any{ttm}
			}
			if len(p.StepAdjustments) > 0 {
				var steps []any
				for _, sa := range p.StepAdjustments {
					sm := map[string]any{}
					if sa.ScalingAdjustment != nil {
						sm["scaling_adjustment"] = *sa.ScalingAdjustment
					}
					if sa.MetricIntervalLowerBound != nil {
						sm["metric_interval_lower_bound"] = strconv.FormatFloat(*sa.MetricIntervalLowerBound, 'f', -1, 64)
					}
					if sa.MetricIntervalUpperBound != nil {
						sm["metric_interval_upper_bound"] = strconv.FormatFloat(*sa.MetricIntervalUpperBound, 'f', -1, 64)
					}
					steps = append(steps, sm)
				}
				cfg["step_adjustment"] = steps
			}
			kids = append(kids, model.Resource{
				Service: "autoscaling", Type: "policy", TFType: "aws_autoscaling_policy",
				Region: parent.Region, Account: parent.Account,
				ID: asg + "/" + name, ImportID: asg + "/" + name, Config: cfg,
			})
		}
	}

	if sa, err := cl.DescribeScheduledActions(ctx, &autoscaling.DescribeScheduledActionsInput{AutoScalingGroupName: &asg}); err == nil {
		for _, s := range sa.ScheduledUpdateGroupActions {
			name := aws.ToString(s.ScheduledActionName)
			cfg := map[string]any{
				"scheduled_action_name":  name,
				"autoscaling_group_name": asg,
			}
			if v := aws.ToString(s.Recurrence); v != "" {
				cfg["recurrence"] = v
			}
			if s.MinSize != nil {
				cfg["min_size"] = *s.MinSize
			}
			if s.MaxSize != nil {
				cfg["max_size"] = *s.MaxSize
			}
			if s.DesiredCapacity != nil {
				cfg["desired_capacity"] = *s.DesiredCapacity
			}
			if s.StartTime != nil {
				cfg["start_time"] = s.StartTime.UTC().Format(time.RFC3339)
			}
			if s.EndTime != nil {
				cfg["end_time"] = s.EndTime.UTC().Format(time.RFC3339)
			}
			if v := aws.ToString(s.TimeZone); v != "" {
				cfg["time_zone"] = v
			}
			kids = append(kids, model.Resource{
				Service: "autoscaling", Type: "schedule", TFType: "aws_autoscaling_schedule",
				Region: parent.Region, Account: parent.Account,
				ID: asg + "/" + name, ImportID: asg + "/" + name, Config: cfg,
			})
		}
	}

	if lh, err := cl.DescribeLifecycleHooks(ctx, &autoscaling.DescribeLifecycleHooksInput{AutoScalingGroupName: &asg}); err == nil {
		for _, h := range lh.LifecycleHooks {
			name := aws.ToString(h.LifecycleHookName)
			cfg := map[string]any{
				"name":                   name,
				"autoscaling_group_name": asg,
				"lifecycle_transition":   aws.ToString(h.LifecycleTransition),
			}
			if v := aws.ToString(h.DefaultResult); v != "" {
				cfg["default_result"] = v
			}
			if h.HeartbeatTimeout != nil {
				cfg["heartbeat_timeout"] = *h.HeartbeatTimeout
			}
			if v := aws.ToString(h.NotificationTargetARN); v != "" {
				cfg["notification_target_arn"] = v
			}
			if v := aws.ToString(h.RoleARN); v != "" {
				cfg["role_arn"] = v
			}
			if v := aws.ToString(h.NotificationMetadata); v != "" {
				cfg["notification_metadata"] = v
			}
			kids = append(kids, model.Resource{
				Service: "autoscaling", Type: "lifecycle-hook", TFType: "aws_autoscaling_lifecycle_hook",
				Region: parent.Region, Account: parent.Account,
				ID: asg + "/" + name, ImportID: asg + "/" + name, Config: cfg,
			})
		}
	}
	return kids, nil
}
