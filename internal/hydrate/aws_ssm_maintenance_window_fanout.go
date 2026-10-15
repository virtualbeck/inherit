package hydrate

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_ssm_maintenance_window", fanoutMaintenanceWindow)
}

func fanoutMaintenanceWindow(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := ssm.NewFromConfig(c.Cfg(parent.Region))
	windowID := parent.ID

	var kids []model.Resource

	targetSch, err := schemaFor("aws_ssm_maintenance_window_target")
	if err != nil {
		return nil, err
	}
	var targetToken *string
	for {
		out, err := cl.DescribeMaintenanceWindowTargets(ctx, &ssm.DescribeMaintenanceWindowTargetsInput{
			WindowId: &windowID, NextToken: targetToken,
		})
		if err != nil {
			return kids, err
		}
		for _, t := range out.Targets {
			cfg, err := Generic(t, targetSch, nil)
			if err != nil {
				continue
			}
			cfg["window_id"] = windowID
			id := aws.ToString(t.WindowTargetId)
			kids = append(kids, model.Resource{
				Service: "ssm", Type: "maintenancewindowtarget", TFType: "aws_ssm_maintenance_window_target",
				Region: parent.Region, Account: parent.Account,
				ID: windowID + "/" + id, ImportID: windowID + "/" + id,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		targetToken = out.NextToken
	}

	// only Get returns TaskInvocationParameters
	taskSch, err := schemaFor("aws_ssm_maintenance_window_task")
	if err != nil {
		return kids, err
	}
	var taskToken *string
	for {
		out, err := cl.DescribeMaintenanceWindowTasks(ctx, &ssm.DescribeMaintenanceWindowTasksInput{
			WindowId: &windowID, NextToken: taskToken,
		})
		if err != nil {
			return kids, err
		}
		for _, t := range out.Tasks {
			taskID := aws.ToString(t.WindowTaskId)
			full, err := cl.GetMaintenanceWindowTask(ctx, &ssm.GetMaintenanceWindowTaskInput{
				WindowId: &windowID, WindowTaskId: &taskID,
			})
			if err != nil {
				continue
			}
			// union fields need the _parameters suffix
			cfg, err := Generic(full, taskSch, map[string]string{
				"automation":     "automation_parameters",
				"lambda":         "lambda_parameters",
				"run_command":    "run_command_parameters",
				"step_functions": "step_functions_parameters",
			})
			if err != nil {
				continue
			}
			cfg["window_id"] = windowID
			ssmTaskAttachParameters(cfg, full.TaskInvocationParameters)
			kids = append(kids, model.Resource{
				Service: "ssm", Type: "maintenancewindowtask", TFType: "aws_ssm_maintenance_window_task",
				Region: parent.Region, Account: parent.Account,
				ID: windowID + "/" + taskID, ImportID: windowID + "/" + taskID,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		taskToken = out.NextToken
	}

	return kids, nil
}

// Parameter maps become repeated parameter blocks.
func ssmTaskAttachParameters(cfg map[string]any, tip *ssmtypes.MaintenanceWindowTaskInvocationParameters) {
	if tip == nil {
		return
	}
	attach := func(subKey string, params map[string][]string) {
		if len(params) == 0 {
			return
		}
		tipm := ssmSingleBlock(cfg, "task_invocation_parameters")
		subm := ssmSingleBlock(tipm, subKey)
		subm["parameter"] = ssmParameterList(params)
	}
	if tip.RunCommand != nil {
		attach("run_command_parameters", tip.RunCommand.Parameters)
	}
	if tip.Automation != nil {
		attach("automation_parameters", tip.Automation.Parameters)
	}
}

// ssmSingleBlock returns m[k]'s map, creating it if absent.
func ssmSingleBlock(m map[string]any, k string) map[string]any {
	switch v := m[k].(type) {
	case []any:
		if len(v) == 1 {
			if sub, ok := v[0].(map[string]any); ok {
				return sub
			}
		}
	case map[string]any:
		return v
	}
	sub := map[string]any{}
	m[k] = []any{sub}
	return sub
}

func ssmParameterList(params map[string][]string) []any {
	names := make([]string, 0, len(params))
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]any, 0, len(names))
	for _, name := range names {
		out = append(out, map[string]any{"name": name, "values": toAny(params[name])})
	}
	return out
}
