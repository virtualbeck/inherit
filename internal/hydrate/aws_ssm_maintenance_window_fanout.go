package hydrate

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_ssm_maintenance_window", fanoutMaintenanceWindow)
}

// fanoutMaintenanceWindow expands a maintenance window into its registered
// targets and tasks, both separate top-level resources in the provider.
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

	// GetMaintenanceWindowTask (singular, per task) is called for each task
	// rather than relying on DescribeMaintenanceWindowTasks alone: the list
	// call doesn't return TaskInvocationParameters at all (only the
	// deprecated TaskParameters/LoggingInfo), so the actual "what does this
	// task run" detail -- the most load-bearing part of the resource --
	// would otherwise be silently absent from every imported task.
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
			// The union's own field names (Automation/Lambda/RunCommand/
			// StepFunctions) snake-case to e.g. "run_command", but the
			// schema's matching nested blocks are all suffixed
			// "_parameters" (run_command_parameters, ...) -- with no
			// override, filterBlock treats the whole thing as an unknown
			// key and drops the ENTIRE sub-block (comment, timeout_seconds,
			// document_version, everything), not just the one field that
			// actually needed remapping.
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

// ssmTaskAttachParameters attaches each task-type's own "parameter" block(s)
// directly from the raw SDK struct: SSM's RunCommand/Automation
// TaskInvocationParameters both carry their parameters as
// map[string][]string, but the schema wants a repeated
// `parameter { name, values }` block -- a map-vs-list-of-struct shape
// Generic() has no way to bridge on its own. Builds the enclosing
// task_invocation_parameters/*_parameters maps by hand if Generic() dropped
// them entirely, since a sub-block whose ONLY meaningful content is its
// parameters would otherwise vanish outright -- an all-empty nested block
// never survives filterNested's "keep only if non-empty" check.
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

// ssmSingleBlock returns the one map inside m[k], whether Generic() already
// represented it as a bare map or (its actual convention for a max-1 nested
// block, both task_invocation_parameters and run_command_parameters use
// nesting mode "list") a one-element list -- creating an empty one, wired
// back into m the same list-wrapped way, if k is absent so a value can still
// be attached even when Generic() dropped the whole sub-block as empty.
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

// ssmParameterList converts map[string][]string into the schema's repeated
// {name, values} block shape, sorted by name for deterministic output.
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
