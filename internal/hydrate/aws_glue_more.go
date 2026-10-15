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

// enabled is derived; ON_DEMAND/EVENT diff once.
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

// HidePassword makes AWS mask connection passwords.
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
