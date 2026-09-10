package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_cloudwatch_dashboard", hydrateDashboard)
	register("aws_cloudwatch_composite_alarm", hydrateCompositeAlarm)
	register("aws_cloudwatch_metric_alarm", hydrateMetricAlarm)
	register("aws_cloudtrail", hydrateCloudTrail)
	register("aws_cloudtrail_event_data_store", genericHydratorOverride(
		"aws_cloudtrail_event_data_store", fetchEventDataStore,
		map[string]string{"advanced_event_selectors": "advanced_event_selector", "field_selectors": "field_selector"},
	))
	register("aws_cloudwatch_log_group", hydrateLogGroup)
}

// fetchEventDataStore's AdvancedEventSelectors/FieldSelectors (plural)
// don't snake-case to the schema's advanced_event_selector/field_selector
// (singular block names) -- an override, not a nested-block-drop issue.
func fetchEventDataStore(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	arn := r.ARN
	out, err := ct.NewFromConfig(c.Cfg(r.Region)).GetEventDataStore(ctx, &ct.GetEventDataStoreInput{EventDataStore: &arn})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hydrateDashboard(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := cw.NewFromConfig(c.Cfg(r.Region)).GetDashboard(ctx, &cw.GetDashboardInput{DashboardName: &r.ID})
	if err != nil {
		return nil, err
	}
	body := aws.ToString(out.DashboardBody)
	if body == "" {
		return nil, fmt.Errorf("empty dashboard body")
	}
	return map[string]any{"dashboard_name": r.ID, "dashboard_body": body}, nil
}

func hydrateCompositeAlarm(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := cw.NewFromConfig(c.Cfg(r.Region)).DescribeAlarms(ctx, &cw.DescribeAlarmsInput{
		AlarmNames: []string{name},
		AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeCompositeAlarm},
	})
	if err != nil {
		return nil, err
	}
	if len(out.CompositeAlarms) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.CompositeAlarms[0]
	cfg := map[string]any{
		"alarm_name": aws.ToString(a.AlarmName),
		"alarm_rule": aws.ToString(a.AlarmRule),
	}
	if v := aws.ToString(a.AlarmDescription); v != "" {
		cfg["alarm_description"] = v
	}
	if a.ActionsEnabled != nil {
		cfg["actions_enabled"] = *a.ActionsEnabled
	}
	if len(a.AlarmActions) > 0 {
		cfg["alarm_actions"] = toAny(a.AlarmActions)
	}
	if len(a.OKActions) > 0 {
		cfg["ok_actions"] = toAny(a.OKActions)
	}
	return cfg, nil
}

// Metric alarms: Dimensions is a list in the API, a map in Terraform; the
// metric_query graph needs its own shaping (same lesson as the former2 corpus).
func hydrateMetricAlarm(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_cloudwatch_metric_alarm")
	if err != nil {
		return nil, err
	}
	out, err := cw.NewFromConfig(c.Cfg(r.Region)).DescribeAlarms(ctx, &cw.DescribeAlarmsInput{
		AlarmNames: []string{r.ID}, AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm},
	})
	if err != nil {
		return nil, err
	}
	if len(out.MetricAlarms) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.MetricAlarms[0]
	cfg, err := Generic(a, sch, nil)
	if err != nil {
		return nil, err
	}
	delete(cfg, "dimensions")
	if len(a.Dimensions) > 0 {
		dims := map[string]any{}
		for _, d := range a.Dimensions {
			dims[aws.ToString(d.Name)] = aws.ToString(d.Value)
		}
		cfg["dimensions"] = dims
	}
	delete(cfg, "metrics")
	delete(cfg, "metric_query")
	for _, mq := range a.Metrics {
		q := map[string]any{"id": aws.ToString(mq.Id)}
		if v := aws.ToString(mq.Expression); v != "" {
			q["expression"] = v
		}
		if v := aws.ToString(mq.Label); v != "" {
			q["label"] = v
		}
		if mq.ReturnData != nil {
			q["return_data"] = *mq.ReturnData
		}
		if v := aws.ToString(mq.AccountId); v != "" {
			q["account_id"] = v
		}
		if ms := mq.MetricStat; ms != nil && ms.Metric != nil {
			m := map[string]any{
				"metric_name": aws.ToString(ms.Metric.MetricName),
				"namespace":   aws.ToString(ms.Metric.Namespace),
				"stat":        aws.ToString(ms.Stat),
			}
			if ms.Period != nil {
				m["period"] = *ms.Period
			}
			if u := string(ms.Unit); u != "" {
				m["unit"] = u
			}
			if len(ms.Metric.Dimensions) > 0 {
				md := map[string]any{}
				for _, d := range ms.Metric.Dimensions {
					md[aws.ToString(d.Name)] = aws.ToString(d.Value)
				}
				m["dimensions"] = md
			}
			q["metric"] = []any{m}
		}
		existing, _ := cfg["metric_query"].([]any)
		cfg["metric_query"] = append(existing, q)
	}
	return cfg, nil
}

func hydrateCloudTrail(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ct.NewFromConfig(c.Cfg(r.Region)).GetTrail(ctx, &ct.GetTrailInput{Name: &r.ARN})
	if err != nil {
		return nil, err
	}
	t := out.Trail
	cfg := map[string]any{
		"name":           aws.ToString(t.Name),
		"s3_bucket_name": aws.ToString(t.S3BucketName),
	}
	for k, v := range map[string]string{
		"s3_key_prefix":              aws.ToString(t.S3KeyPrefix),
		"cloud_watch_logs_group_arn": aws.ToString(t.CloudWatchLogsLogGroupArn),
		"cloud_watch_logs_role_arn":  aws.ToString(t.CloudWatchLogsRoleArn),
		"kms_key_id":                 aws.ToString(t.KmsKeyId),
	} {
		if v != "" {
			cfg[k] = v
		}
	}
	if t.IncludeGlobalServiceEvents != nil {
		cfg["include_global_service_events"] = *t.IncludeGlobalServiceEvents
	}
	if t.IsMultiRegionTrail != nil {
		cfg["is_multi_region_trail"] = *t.IsMultiRegionTrail
	}
	if t.IsOrganizationTrail != nil {
		cfg["is_organization_trail"] = *t.IsOrganizationTrail
	}
	if t.LogFileValidationEnabled != nil {
		cfg["enable_log_file_validation"] = *t.LogFileValidationEnabled
	}
	// GetTrail doesn't return event/insight selectors at all -- separate
	// calls. Data-event logging (S3/Lambda/DynamoDB) and Insights are both
	// common real-world trail customizations; dropping them silently would
	// have understated a trail's actual configuration entirely.
	cl := ct.NewFromConfig(c.Cfg(r.Region))
	if es, eerr := cl.GetEventSelectors(ctx, &ct.GetEventSelectorsInput{TrailName: &r.ARN}); eerr == nil {
		if len(es.EventSelectors) > 0 {
			var sels []any
			for _, s := range es.EventSelectors {
				sel := map[string]any{}
				if s.IncludeManagementEvents != nil {
					sel["include_management_events"] = *s.IncludeManagementEvents
				}
				if v := string(s.ReadWriteType); v != "" {
					sel["read_write_type"] = v
				}
				if len(s.ExcludeManagementEventSources) > 0 {
					sel["exclude_management_event_sources"] = toAny(s.ExcludeManagementEventSources)
				}
				if len(s.DataResources) > 0 {
					var drs []any
					for _, dr := range s.DataResources {
						drs = append(drs, map[string]any{
							"type":   aws.ToString(dr.Type),
							"values": toAny(dr.Values),
						})
					}
					sel["data_resource"] = drs
				}
				sels = append(sels, sel)
			}
			cfg["event_selector"] = sels
		}
	}
	if is, ierr := cl.GetInsightSelectors(ctx, &ct.GetInsightSelectorsInput{TrailName: &r.ARN}); ierr == nil && len(is.InsightSelectors) > 0 {
		var sels []any
		for _, s := range is.InsightSelectors {
			if v := string(s.InsightType); v != "" {
				sels = append(sels, map[string]any{"insight_type": v})
			}
		}
		if len(sels) > 0 {
			cfg["insight_selector"] = sels
		}
	}
	return cfg, nil
}

func hydrateLogGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_cloudwatch_log_group")
	if err != nil {
		return nil, err
	}
	name := r.ID
	out, err := cwl.NewFromConfig(c.Cfg(r.Region)).DescribeLogGroups(ctx, &cwl.DescribeLogGroupsInput{
		LogGroupNamePrefix: &name,
	})
	if err != nil {
		return nil, err
	}
	for _, g := range out.LogGroups {
		if aws.ToString(g.LogGroupName) == name {
			return Generic(g, sch, map[string]string{"log_group_name": "name"})
		}
	}
	return nil, fmt.Errorf("not found")
}
