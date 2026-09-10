package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amp"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { register("aws_prometheus_workspace", hydrateAMPWorkspace) }

func hydrateAMPWorkspace(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := amp.NewFromConfig(c.Cfg(r.Region))
	id := r.ID
	out, err := cl.DescribeWorkspace(ctx, &amp.DescribeWorkspaceInput{WorkspaceId: &id})
	if err != nil || out.Workspace == nil {
		return nil, err
	}
	w := out.Workspace
	cfg := map[string]any{}
	if v := aws.ToString(w.Alias); v != "" {
		cfg["alias"] = v
	}
	if v := aws.ToString(w.KmsKeyArn); v != "" {
		cfg["kms_key_arn"] = v
	}
	// logging_configuration is a separate API call, not part of
	// DescribeWorkspace's own response -- most workspaces don't have one
	// configured, so a NotFound-style error here just means "not set".
	if lc, lerr := cl.DescribeLoggingConfiguration(ctx, &amp.DescribeLoggingConfigurationInput{WorkspaceId: &id}); lerr == nil && lc.LoggingConfiguration != nil {
		if v := aws.ToString(lc.LoggingConfiguration.LogGroupArn); v != "" {
			cfg["logging_configuration"] = []any{map[string]any{"log_group_arn": v}}
		}
	}
	return cfg, nil
}
