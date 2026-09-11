package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_eks_cluster", fanoutEKS)
}

// fanoutEKS expands a cluster into its node groups, Fargate profiles and addons.
func fanoutEKS(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := eks.NewFromConfig(c.Cfg(parent.Region))
	name := parent.ID
	var kids []model.Resource

	if ng, err := cl.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: &name}); err == nil {
		for _, n := range ng.Nodegroups {
			d, err := cl.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{ClusterName: &name, NodegroupName: aws.String(n)})
			if err != nil || d.Nodegroup == nil {
				continue
			}
			g := d.Nodegroup
			cfg := map[string]any{
				"cluster_name":    name,
				"node_group_name": aws.ToString(g.NodegroupName),
				"node_role_arn":   aws.ToString(g.NodeRole),
				"subnet_ids":      toAny(g.Subnets),
			}
			if g.ScalingConfig != nil {
				cfg["scaling_config"] = map[string]any{
					"desired_size": aws.ToInt32(g.ScalingConfig.DesiredSize),
					"max_size":     aws.ToInt32(g.ScalingConfig.MaxSize),
					"min_size":     aws.ToInt32(g.ScalingConfig.MinSize),
				}
			}
			if len(g.InstanceTypes) > 0 {
				cfg["instance_types"] = toAny(g.InstanceTypes)
			}
			if v := string(g.AmiType); v != "" {
				cfg["ami_type"] = v
			}
			if v := string(g.CapacityType); v != "" {
				cfg["capacity_type"] = v
			}
			if g.DiskSize != nil {
				cfg["disk_size"] = *g.DiskSize
			}
			if len(g.Labels) > 0 {
				m := map[string]any{}
				for k, v := range g.Labels {
					m[k] = v
				}
				cfg["labels"] = m
			}
			if v := aws.ToString(g.ReleaseVersion); v != "" {
				cfg["release_version"] = v
			}
			if v := aws.ToString(g.Version); v != "" {
				cfg["version"] = v
			}
			if uc := g.UpdateConfig; uc != nil {
				m := map[string]any{}
				if uc.MaxUnavailable != nil {
					m["max_unavailable"] = *uc.MaxUnavailable
				}
				if uc.MaxUnavailablePercentage != nil {
					m["max_unavailable_percentage"] = *uc.MaxUnavailablePercentage
				}
				if v := string(uc.UpdateStrategy); v != "" {
					m["update_strategy"] = v
				}
				if len(m) > 0 {
					cfg["update_config"] = []any{m}
				}
			}
			if ra := g.RemoteAccess; ra != nil {
				m := map[string]any{}
				if v := aws.ToString(ra.Ec2SshKey); v != "" {
					m["ec2_ssh_key"] = v
				}
				if len(ra.SourceSecurityGroups) > 0 {
					m["source_security_group_ids"] = toAny(ra.SourceSecurityGroups)
				}
				if len(m) > 0 {
					cfg["remote_access"] = []any{m}
				}
			}
			if lt := g.LaunchTemplate; lt != nil && aws.ToString(lt.Version) != "" {
				m := map[string]any{"version": aws.ToString(lt.Version)}
				if v := aws.ToString(lt.Id); v != "" {
					m["id"] = v
				}
				if v := aws.ToString(lt.Name); v != "" {
					m["name"] = v
				}
				cfg["launch_template"] = []any{m}
			}
			if len(g.Taints) > 0 {
				var ts []any
				for _, t := range g.Taints {
					tm := map[string]any{"key": aws.ToString(t.Key), "effect": string(t.Effect)}
					if v := aws.ToString(t.Value); v != "" {
						tm["value"] = v
					}
					ts = append(ts, tm)
				}
				cfg["taint"] = ts
			}
			if len(g.Tags) > 0 {
				cfg["tags"] = g.Tags
			}
			kids = append(kids, model.Resource{
				Service: "eks", Type: "nodegroup", TFType: "aws_eks_node_group",
				Region: parent.Region, Account: parent.Account,
				ID:     name + ":" + aws.ToString(g.NodegroupName),
				Tags:   g.Tags,
				Config: cfg,
			})
		}
	}

	if fp, err := cl.ListFargateProfiles(ctx, &eks.ListFargateProfilesInput{ClusterName: &name}); err == nil {
		for _, f := range fp.FargateProfileNames {
			d, err := cl.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{ClusterName: &name, FargateProfileName: aws.String(f)})
			if err != nil || d.FargateProfile == nil {
				continue
			}
			p := d.FargateProfile
			cfg := map[string]any{
				"cluster_name":           name,
				"fargate_profile_name":   aws.ToString(p.FargateProfileName),
				"pod_execution_role_arn": aws.ToString(p.PodExecutionRoleArn),
			}
			if len(p.Subnets) > 0 {
				cfg["subnet_ids"] = toAny(p.Subnets)
			}
			var sel []any
			for _, s := range p.Selectors {
				m := map[string]any{"namespace": aws.ToString(s.Namespace)}
				if len(s.Labels) > 0 {
					lm := map[string]any{}
					for k, v := range s.Labels {
						lm[k] = v
					}
					m["labels"] = lm
				}
				sel = append(sel, m)
			}
			if len(sel) > 0 {
				cfg["selector"] = sel
			}
			if len(p.Tags) > 0 {
				cfg["tags"] = p.Tags
			}
			kids = append(kids, model.Resource{
				Service: "eks", Type: "fargateprofile", TFType: "aws_eks_fargate_profile",
				Region: parent.Region, Account: parent.Account,
				ID:     name + ":" + aws.ToString(p.FargateProfileName),
				Tags:   p.Tags,
				Config: cfg,
			})
		}
	}

	if ad, err := cl.ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &name}); err == nil {
		for _, a := range ad.Addons {
			d, err := cl.DescribeAddon(ctx, &eks.DescribeAddonInput{ClusterName: &name, AddonName: aws.String(a)})
			if err != nil || d.Addon == nil {
				continue
			}
			cfg := map[string]any{
				"cluster_name": name,
				"addon_name":   aws.ToString(d.Addon.AddonName),
			}
			if v := aws.ToString(d.Addon.AddonVersion); v != "" {
				cfg["addon_version"] = v
			}
			if v := aws.ToString(d.Addon.ServiceAccountRoleArn); v != "" {
				cfg["service_account_role_arn"] = v
			}
			if v := aws.ToString(d.Addon.ConfigurationValues); v != "" {
				cfg["configuration_values"] = v
			}
			if len(d.Addon.Tags) > 0 {
				cfg["tags"] = d.Addon.Tags
			}
			// PodIdentityAssociations on the addon is just a list of bare
			// association IDs -- DescribePodIdentityAssociation per id is
			// the only way to get the actual service_account/role_arn the
			// schema needs.
			var pias []any
			for _, assocID := range d.Addon.PodIdentityAssociations {
				assocID := assocID
				pd, perr := cl.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
					ClusterName: &name, AssociationId: &assocID,
				})
				if perr != nil || pd.Association == nil {
					continue
				}
				pias = append(pias, map[string]any{
					"service_account": aws.ToString(pd.Association.ServiceAccount),
					"role_arn":        aws.ToString(pd.Association.RoleArn),
				})
			}
			if len(pias) > 0 {
				cfg["pod_identity_association"] = pias
			}
			kids = append(kids, model.Resource{
				Service: "eks", Type: "addon", TFType: "aws_eks_addon",
				Region: parent.Region, Account: parent.Account,
				ID:     name + ":" + aws.ToString(d.Addon.AddonName),
				Tags:   d.Addon.Tags,
				Config: cfg,
			})
		}
	}

	return kids, nil
}
