package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_grafana_workspace", hydrateGrafanaWorkspace) }

// Hand-built: nested auth, renamed role, separate config call.
func hydrateGrafanaWorkspace(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := grafana.NewFromConfig(c.Cfg(r.Region))
	id := r.ID
	out, err := cl.DescribeWorkspace(ctx, &grafana.DescribeWorkspaceInput{WorkspaceId: &id})
	if err != nil || out.Workspace == nil {
		return nil, err
	}
	w := out.Workspace
	cfg := map[string]any{
		"account_access_type": string(w.AccountAccessType),
		"permission_type":     string(w.PermissionType),
	}
	if w.Authentication != nil && len(w.Authentication.Providers) > 0 {
		var provs []any
		for _, p := range w.Authentication.Providers {
			provs = append(provs, string(p))
		}
		cfg["authentication_providers"] = provs
	}
	if v := aws.ToString(w.Name); v != "" {
		cfg["name"] = v
	}
	if v := aws.ToString(w.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(w.WorkspaceRoleArn); v != "" {
		cfg["role_arn"] = v
	}
	if v := aws.ToString(w.GrafanaVersion); v != "" {
		cfg["grafana_version"] = v
	}
	if v := aws.ToString(w.StackSetName); v != "" {
		cfg["stack_set_name"] = v
	}
	if v := aws.ToString(w.OrganizationRoleName); v != "" {
		cfg["organization_role_name"] = v
	}
	if v := aws.ToString(w.KmsKeyId); v != "" {
		cfg["kms_key_id"] = v
	}
	if len(w.OrganizationalUnits) > 0 {
		cfg["organizational_units"] = toAny(w.OrganizationalUnits)
	}
	if len(w.DataSources) > 0 {
		var ds []any
		for _, d := range w.DataSources {
			ds = append(ds, string(d))
		}
		cfg["data_sources"] = ds
	}
	if len(w.NotificationDestinations) > 0 {
		var nd []any
		for _, d := range w.NotificationDestinations {
			nd = append(nd, string(d))
		}
		cfg["notification_destinations"] = nd
	}
	if nac := w.NetworkAccessControl; nac != nil {
		cfg["network_access_control"] = []any{map[string]any{
			"prefix_list_ids": toAny(nac.PrefixListIds),
			"vpce_ids":        toAny(nac.VpceIds),
		}}
	}
	if vc := w.VpcConfiguration; vc != nil {
		cfg["vpc_configuration"] = []any{map[string]any{
			"subnet_ids":         toAny(vc.SubnetIds),
			"security_group_ids": toAny(vc.SecurityGroupIds),
		}}
	}
	if conf, cerr := cl.DescribeWorkspaceConfiguration(ctx, &grafana.DescribeWorkspaceConfigurationInput{WorkspaceId: &id}); cerr == nil {
		if v := aws.ToString(conf.Configuration); v != "" {
			cfg["configuration"] = v
		}
	}
	return cfg, nil
}
