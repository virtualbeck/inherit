package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_glue_trigger", hydrateGlueTrigger)
	register("aws_glue_connection", hydrateGlueConnection)
	register("aws_glue_workflow", hydrateGlueWorkflow)
}

// hydrateGlueTrigger uses Generic() for the bulk of the shape (Action/
// Predicate/EventBatchingCondition/NotificationProperty all map cleanly to
// their schema names) but "enabled" has no direct API field at all -- the
// real provider's Read derives it from trigger state, and for ON_DEMAND/
// EVENT triggers ANDs that with the trigger's *prior* Terraform state
// (`d.Get(names.AttrEnabled)`), which is always the zero value (false) right
// after import. That makes "enabled" a one-time provider-directive-style
// diff for ON_DEMAND/EVENT triggers specifically (same known-unfixable
// category as lambda's `publish`) -- SCHEDULED/CONDITIONAL triggers don't
// have that quirk since their enabled state comes straight from
// State==ACTIVATED/ACTIVATING, so this best-effort computation is exactly
// right for them and only wrong (for one plan) for the other two types.
func hydrateGlueTrigger(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetTrigger(ctx, &glue.GetTriggerInput{Name: &name})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_glue_trigger")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.Trigger, sch, nil)
	if err != nil {
		return nil, err
	}
	switch out.Trigger.State {
	case gluetypes.TriggerStateActivated, gluetypes.TriggerStateActivating,
		gluetypes.TriggerStateCreated, gluetypes.TriggerStateCreating:
		cfg["enabled"] = true
	default:
		cfg["enabled"] = false
	}
	return cfg, nil
}

// hydrateGlueConnection forces HidePassword so AWS itself masks any
// PASSWORD-family value inside connection_properties with asterisks before
// it ever reaches inherit -- GetConnection returns the real plaintext
// password by default (HidePassword defaults to false), and this is
// otherwise exactly the kind of real secret this project has deliberately
// never emitted elsewhere (same discipline as MWAA's
// airflow_configuration_options).
func hydrateGlueConnection(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetConnection(ctx, &glue.GetConnectionInput{Name: &name, HidePassword: true})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_glue_connection")
	if err != nil {
		return nil, err
	}
	return Generic(out.Connection, sch, nil)
}

func hydrateGlueWorkflow(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetWorkflow(ctx, &glue.GetWorkflowInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Workflow.Name)}
	if v := aws.ToString(out.Workflow.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToInt32(out.Workflow.MaxConcurrentRuns); v != 0 {
		cfg["max_concurrent_runs"] = v
	}
	if len(out.Workflow.DefaultRunProperties) > 0 {
		cfg["default_run_properties"] = out.Workflow.DefaultRunProperties
	}
	return cfg, nil
}
