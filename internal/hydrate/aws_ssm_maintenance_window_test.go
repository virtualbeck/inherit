package hydrate

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func TestSSMParameterList(t *testing.T) {
	got := ssmParameterList(map[string][]string{
		"commands": {"echo hello"},
		"workDir":  {"/tmp"},
	})
	want := []any{
		map[string]any{"name": "commands", "values": []any{"echo hello"}},
		map[string]any{"name": "workDir", "values": []any{"/tmp"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ssmParameterList mismatch:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestSSMSingleBlock(t *testing.T) {
	// list-wrapped (Generic()'s actual convention for a max-1 nested block)
	m := map[string]any{"x": []any{map[string]any{"a": 1}}}
	sub := ssmSingleBlock(m, "x")
	if sub["a"] != 1 {
		t.Errorf("expected existing list-wrapped block to be found, got %#v", sub)
	}

	// bare map, in case some other path represents it that way
	m2 := map[string]any{"x": map[string]any{"a": 2}}
	sub2 := ssmSingleBlock(m2, "x")
	if sub2["a"] != 2 {
		t.Errorf("expected existing bare-map block to be found, got %#v", sub2)
	}

	// missing entirely -- must create one, wired back list-wrapped
	m3 := map[string]any{}
	sub3 := ssmSingleBlock(m3, "x")
	sub3["a"] = 3
	list, ok := m3["x"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected a freshly created one-element list, got %#v", m3["x"])
	}
	if list[0].(map[string]any)["a"] != 3 {
		t.Errorf("mutation through the returned map didn't reach m3: %#v", m3)
	}
}

// The union's own field names (Automation/Lambda/RunCommand/StepFunctions)
// snake-case to e.g. "run_command", not the schema's "run_command_parameters"
// -- without the override in place, filterBlock drops the whole sub-block
// (comment, timeout_seconds, everything) as an unrecognized key, and
// task_invocation_parameters.parameter (map[string][]string in the SDK,
// a repeated {name,values} block in the schema) needs ssmTaskAttachParameters
// regardless, since Generic() can't bridge that shape on its own.
func TestSSMTaskInvocationParametersEndToEnd(t *testing.T) {
	sch, err := schemaFor("aws_ssm_maintenance_window_task")
	if err != nil {
		t.Fatal(err)
	}
	overrides := map[string]string{
		"automation":     "automation_parameters",
		"lambda":         "lambda_parameters",
		"run_command":    "run_command_parameters",
		"step_functions": "step_functions_parameters",
	}

	full := struct {
		Name                     *string
		TaskInvocationParameters *ssmtypes.MaintenanceWindowTaskInvocationParameters
	}{
		Name: aws.String("x"),
		TaskInvocationParameters: &ssmtypes.MaintenanceWindowTaskInvocationParameters{
			RunCommand: &ssmtypes.MaintenanceWindowRunCommandParameters{
				Comment:        aws.String("inherit fixture"),
				TimeoutSeconds: aws.Int32(600),
				Parameters:     map[string][]string{"commands": {"echo hello"}},
			},
		},
	}
	cfg, err := Generic(full, sch, overrides)
	if err != nil {
		t.Fatal(err)
	}
	ssmTaskAttachParameters(cfg, full.TaskInvocationParameters)

	tip, ok := cfg["task_invocation_parameters"].([]any)
	if !ok || len(tip) != 1 {
		t.Fatalf("expected a one-element task_invocation_parameters list, got %#v", cfg["task_invocation_parameters"])
	}
	rc, ok := tip[0].(map[string]any)["run_command_parameters"].([]any)
	if !ok || len(rc) != 1 {
		t.Fatalf("expected a one-element run_command_parameters list, got %#v", tip[0])
	}
	rcm := rc[0].(map[string]any)
	if rcm["comment"] != "inherit fixture" {
		t.Errorf("comment dropped: %#v", rcm)
	}
	if rcm["timeout_seconds"] != float64(600) {
		t.Errorf("timeout_seconds dropped: %#v", rcm)
	}
	params, ok := rcm["parameter"].([]any)
	if !ok || len(params) != 1 {
		t.Fatalf("expected one parameter entry, got %#v", rcm["parameter"])
	}
	if p := params[0].(map[string]any); p["name"] != "commands" {
		t.Errorf("parameter entry wrong: %#v", p)
	}

	// a task whose ONLY meaningful run-command content is its parameters
	// (comment/timeout_seconds both empty) must still get the block --
	// Generic() alone would drop an all-empty nested block entirely.
	full.TaskInvocationParameters.RunCommand.Comment = nil
	full.TaskInvocationParameters.RunCommand.TimeoutSeconds = nil
	cfg2, err := Generic(full, sch, overrides)
	if err != nil {
		t.Fatal(err)
	}
	ssmTaskAttachParameters(cfg2, full.TaskInvocationParameters)
	if _, ok := cfg2["task_invocation_parameters"]; !ok {
		t.Error("params-only task_invocation_parameters was dropped entirely")
	}
}
