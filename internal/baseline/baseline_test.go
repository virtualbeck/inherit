package baseline

import (
	"regexp"
	"testing"

	"github.com/virtualbeck/inherit/model"
)

func res(tfType, id string, cfg map[string]any, tags map[string]string) model.Resource {
	return model.Resource{TFType: tfType, ID: id, ARN: "arn:aws:x:us-east-2:111111111111:" + id, Region: "us-east-2", Config: cfg, Tags: tags}
}

func TestMarkBuiltInFingerprints(t *testing.T) {
	cases := []struct {
		r    model.Resource
		want string
	}{
		{res("aws_lambda_function", "aws-controltower-NotificationForwarder", map[string]any{"function_name": "aws-controltower-NotificationForwarder"}, nil), ControlTower},
		{res("aws_cloudwatch_event_rule", "AWSControlTowerManagedRule", map[string]any{"name": "AWSControlTowerManagedRule"}, nil), ControlTower},
		{res("aws_ssm_association", "a-1", map[string]any{"association_name": "AWSQuickSetupType-SSM"}, nil), QuickSetup},
		{res("aws_lambda_function", "delete-name-tags-us-east-2-a1b2", map[string]any{"function_name": "delete-name-tags-us-east-2-a1b2"}, map[string]string{"QuickSetupID": "x"}), QuickSetup},
		{res("aws_cloudformation_stack", "StackSet-org-baseline-1/uuid", map[string]any{"name": "StackSet-org-baseline-1"}, nil), StackSet},
		// shape seen on a real account
		{res("aws_ssm_association", "a-2", map[string]any{"association_name": "GuardDutyRuntimeMonitoring-do-not-delete",
			"name": "AmazonGuardDuty-ConfigureRuntimeMonitoringSsmPlugin"}, map[string]string{"GuardDutyManaged": "true"}), GuardDuty},
		{res("aws_ssm_association", "a-3", map[string]any{"association_name": "x", "name": "AmazonGuardDuty-Other"}, nil), GuardDuty},
		{res("aws_ssm_association", "a-4", map[string]any{"association_name": "x", "name": "custom"}, map[string]string{"GuardDutyManaged": "true"}), GuardDuty},
		{res("aws_securityhub_account", "111111111111", map[string]any{}, nil), AccountSetting},
		{res("aws_securityhub_finding_aggregator", "agg", map[string]any{}, nil), AccountSetting},
		{res("aws_resourceexplorer2_index", "idx", map[string]any{"type": "LOCAL"}, nil), AccountSetting},
		{res("aws_resourceexplorer2_view", "v", map[string]any{"name": "DefaultView"}, nil), AccountSetting},
		{res("aws_ssm_service_setting", "/ssm/managed-instance/default-ec2-instance-management-role", map[string]any{}, nil), AccountSetting},
	}
	for _, c := range cases {
		inv := &model.Inventory{Resources: []model.Resource{c.r}}
		Mark(inv, nil)
		if got := inv.Resources[0].Baseline; got != c.want {
			t.Errorf("%s %s: baseline = %q, want %q", c.r.TFType, c.r.ID, got, c.want)
		}
	}
}

func TestMarkLeavesWorkloadAlone(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		res("aws_lambda_function", "app-svc", map[string]any{"function_name": "app-svc"}, map[string]string{"Environment": "dev"}),
		// an app alarm that notifies a Control Tower topic is still the app's
		res("aws_cloudwatch_metric_alarm", "app-5xx", map[string]any{"alarm_name": "app-5xx",
			"alarm_actions": []any{"arn:aws:sns:us-east-2:111111111111:aws-controltower-SecurityNotifications"}}, nil),
		res("aws_resourceexplorer2_view", "team-view", map[string]any{"name": "team-view"}, nil),
	}}
	Mark(inv, nil)
	for _, r := range inv.Resources {
		if r.Baseline != "" {
			t.Errorf("%s %s marked %q; workload must stay unmarked", r.TFType, r.ID, r.Baseline)
		}
	}
}

func TestChildrenInheritTheirParent(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		res("aws_lambda_function", "delete-name-tags-1", map[string]any{"function_name": "delete-name-tags-1"}, map[string]string{"QuickSetupID": "x"}),
		res("aws_lambda_function_recursion_config", "delete-name-tags-1", map[string]any{"function_name": "delete-name-tags-1"}, nil),
		res("aws_lambda_permission", "p", map[string]any{"function_name": "arn:aws:lambda:us-east-2:111111111111:function:delete-name-tags-1"}, nil),
		res("aws_sns_topic", "aws-controltower-SecurityNotifications", map[string]any{"name": "aws-controltower-SecurityNotifications"}, nil),
		res("aws_sns_topic_subscription", "sub", map[string]any{"topic_arn": "arn:aws:x:us-east-2:111111111111:aws-controltower-SecurityNotifications"}, nil),
		res("aws_cloudwatch_event_rule", "StackSet-org-baseline-PatchInvocation", map[string]any{"name": "StackSet-org-baseline-PatchInvocation"}, nil),
		res("aws_cloudwatch_event_target", "t", map[string]any{"rule": "StackSet-org-baseline-PatchInvocation", "target_id": "x"}, nil),
		res("aws_cloudwatch_log_group", "/aws/lambda/delete-name-tags-1", map[string]any{"name": "/aws/lambda/delete-name-tags-1"}, nil),
		res("aws_lambda_function_recursion_config", "app-svc", map[string]any{"function_name": "app-svc"}, nil),
	}}
	got := Mark(inv, nil)
	want := []string{QuickSetup, QuickSetup, QuickSetup, ControlTower, ControlTower, StackSet, StackSet, QuickSetup, ""}
	for i, r := range inv.Resources {
		if r.Baseline != want[i] {
			t.Errorf("%s %s: baseline = %q, want %q", r.TFType, r.ID, r.Baseline, want[i])
		}
	}
	if got[QuickSetup] != 4 || got[ControlTower] != 2 || got[StackSet] != 2 {
		t.Errorf("counts = %v", got)
	}
}

func TestUserPatternsMarkOrganizationSpecificBaseline(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		res("aws_ssm_resource_data_sync", "resource-data-sync", map[string]any{"name": "resource-data-sync",
			"s3_destination": []any{map[string]any{"bucket_name": "222222222222-org-reports"}}}, nil),
	}}
	Mark(inv, []*regexp.Regexp{regexp.MustCompile(`^222222222222-org-reports$`)})
	if got := inv.Resources[0].Baseline; got != UserPattern {
		t.Errorf("baseline = %q, want %q", got, UserPattern)
	}
}
