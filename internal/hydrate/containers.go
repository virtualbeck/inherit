package hydrate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_ecs_cluster", hydrateECSCluster)
	register("aws_ecs_service", hydrateECSService)
	register("aws_ecs_task_definition", hydrateTaskDef)
	register("aws_ecs_capacity_provider", hydrateECSCapacityProvider)
	register("aws_eks_cluster", hydrateEKS)
	register("aws_ecr_repository", hydrateECRRepo)
}

func hydrateECSCluster(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// DescribeClusters returns none of Settings/Configuration/
	// ServiceConnectDefaults unless explicitly asked for via Include (per
	// the SDK's own doc comment: "If this field is omitted, this
	// information isn't included").
	out, err := ecs.NewFromConfig(c.Cfg(r.Region)).DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: []string{r.ID},
		Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings, ecstypes.ClusterFieldConfigurations},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Clusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cl := out.Clusters[0]
	// An INACTIVE cluster (deleted, but still returned by Describe and
	// still visible to the tagging-API sweep for a while after) can't be
	// imported -- same "discovered but not really there" shape as an
	// ECS task definition's non-ACTIVE revisions.
	if aws.ToString(cl.Status) == "INACTIVE" {
		return nil, fmt.Errorf("INACTIVE ECS cluster (deleted)")
	}
	cfg := map[string]any{"name": aws.ToString(cl.ClusterName)}
	var settings []any
	for _, s := range cl.Settings {
		settings = append(settings, map[string]any{"name": string(s.Name), "value": aws.ToString(s.Value)})
	}
	if len(settings) > 0 {
		cfg["setting"] = settings
	}
	if cc := cl.Configuration; cc != nil {
		conf := map[string]any{}
		if ec := cc.ExecuteCommandConfiguration; ec != nil {
			m := map[string]any{}
			if v := aws.ToString(ec.KmsKeyId); v != "" {
				m["kms_key_id"] = v
			}
			if v := string(ec.Logging); v != "" {
				m["logging"] = v
			}
			if len(m) > 0 {
				conf["execute_command_configuration"] = m
			}
		}
		if ms := cc.ManagedStorageConfiguration; ms != nil {
			m := map[string]any{}
			if v := aws.ToString(ms.KmsKeyId); v != "" {
				m["kms_key_id"] = v
			}
			if v := aws.ToString(ms.FargateEphemeralStorageKmsKeyId); v != "" {
				m["fargate_ephemeral_storage_kms_key_id"] = v
			}
			if len(m) > 0 {
				conf["managed_storage_configuration"] = m
			}
		}
		if len(conf) > 0 {
			cfg["configuration"] = conf
		}
	}
	if scd := cl.ServiceConnectDefaults; scd != nil {
		if v := aws.ToString(scd.Namespace); v != "" {
			cfg["service_connect_defaults"] = map[string]any{"namespace": v}
		}
	}
	return cfg, nil
}

func hydrateECSService(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// service ARN tail is .../service/<cluster>/<name>
	cluster := ""
	if p := strings.Split(r.ID, "/"); len(p) >= 2 {
		cluster = p[len(p)-2]
	}
	out, err := ecs.NewFromConfig(c.Cfg(r.Region)).DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster: aws.String(cluster), Services: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Services) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.Services[0]
	// Same "discovered but deleted" shape as the INACTIVE cluster/KMS
	// pending-deletion exclusions above: a deleted service still answers
	// DescribeServices and stays visible to the tagging-API sweep for a
	// while, but can't actually be imported.
	if aws.ToString(s.Status) == "INACTIVE" {
		return nil, fmt.Errorf("INACTIVE ECS service (deleted)")
	}
	// DescribeServices' TaskDefinition can come back as either the bare
	// "family:revision" or the full ARN (AWS echoes back whatever form the
	// service was last created/updated with). The provider's own Read,
	// though, always normalizes to "family:revision" on a fresh import --
	// d.Get("task_definition") is empty (no prior state), which its
	// arn.IsARN check treats as "not an ARN", so it always strips down to
	// family:revision the first time. Match that here so config lines up
	// with what state will actually contain post-import.
	taskDef := aws.ToString(s.TaskDefinition)
	if parts := strings.Split(taskDef, "/"); len(parts) == 2 && strings.HasPrefix(parts[0], "arn:") {
		taskDef = parts[1]
	}
	cfg := map[string]any{
		"name":            aws.ToString(s.ServiceName),
		"cluster":         aws.ToString(s.ClusterArn),
		"task_definition": taskDef,
		"desired_count":   s.DesiredCount,
		"launch_type":     string(s.LaunchType),
	}
	if s.NetworkConfiguration != nil && s.NetworkConfiguration.AwsvpcConfiguration != nil {
		v := s.NetworkConfiguration.AwsvpcConfiguration
		nc := map[string]any{"assign_public_ip": string(v.AssignPublicIp) == "ENABLED"}
		if len(v.Subnets) > 0 {
			nc["subnets"] = toAny(v.Subnets)
		}
		if len(v.SecurityGroups) > 0 {
			nc["security_groups"] = toAny(v.SecurityGroups)
		}
		cfg["network_configuration"] = nc
	}
	if s.HealthCheckGracePeriodSeconds != nil {
		cfg["health_check_grace_period_seconds"] = *s.HealthCheckGracePeriodSeconds
	}
	if dc := s.DeploymentConfiguration; dc != nil && dc.DeploymentCircuitBreaker != nil {
		cb := dc.DeploymentCircuitBreaker
		cfg["deployment_circuit_breaker"] = map[string]any{
			"enable":   cb.Enable,
			"rollback": cb.Rollback,
		}
	}
	var lbs []any
	for _, lb := range s.LoadBalancers {
		m := map[string]any{}
		if v := aws.ToString(lb.ContainerName); v != "" {
			m["container_name"] = v
		}
		if lb.ContainerPort != nil {
			m["container_port"] = *lb.ContainerPort
		}
		if v := aws.ToString(lb.TargetGroupArn); v != "" {
			m["target_group_arn"] = v
		}
		if v := aws.ToString(lb.LoadBalancerName); v != "" {
			m["elb_name"] = v
		}
		if len(m) > 0 {
			lbs = append(lbs, m)
		}
	}
	if len(lbs) > 0 {
		cfg["load_balancer"] = lbs
	}
	// a service using a capacity provider strategy instead of launch_type
	// (very common on Fargate) has nothing else recoverable describing how
	// it actually schedules tasks, so capacity_provider_strategy below
	// matters even though it's rarely the first field anyone thinks to check.
	if v := aws.ToString(s.PlatformVersion); v != "" {
		cfg["platform_version"] = v
	}
	if v := string(s.SchedulingStrategy); v != "" {
		cfg["scheduling_strategy"] = v
	}
	if s.EnableECSManagedTags {
		cfg["enable_ecs_managed_tags"] = true
	}
	if s.EnableExecuteCommand {
		cfg["enable_execute_command"] = true
	}
	if v := string(s.PropagateTags); v != "" {
		cfg["propagate_tags"] = v
	}
	if len(s.CapacityProviderStrategy) > 0 {
		var cps []any
		for _, item := range s.CapacityProviderStrategy {
			m := map[string]any{"capacity_provider": aws.ToString(item.CapacityProvider)}
			if item.Base != 0 {
				m["base"] = item.Base
			}
			if item.Weight != 0 {
				m["weight"] = item.Weight
			}
			cps = append(cps, m)
		}
		cfg["capacity_provider_strategy"] = cps
	}
	if dc := s.DeploymentController; dc != nil {
		cfg["deployment_controller"] = map[string]any{"type": string(dc.Type)}
	}
	if dcfg := s.DeploymentConfiguration; dcfg != nil {
		m := map[string]any{}
		if dcfg.MaximumPercent != nil {
			m["deployment_maximum_percent"] = *dcfg.MaximumPercent
		}
		if dcfg.MinimumHealthyPercent != nil {
			m["deployment_minimum_healthy_percent"] = *dcfg.MinimumHealthyPercent
		}
		for k, v := range m {
			cfg[k] = v
		}
	}
	if len(s.PlacementConstraints) > 0 {
		var pcs []any
		for _, pc := range s.PlacementConstraints {
			m := map[string]any{"type": string(pc.Type)}
			if v := aws.ToString(pc.Expression); v != "" {
				m["expression"] = v
			}
			pcs = append(pcs, m)
		}
		cfg["placement_constraints"] = pcs
	}
	if len(s.PlacementStrategy) > 0 {
		var pss []any
		for _, ps := range s.PlacementStrategy {
			pss = append(pss, map[string]any{"type": string(ps.Type), "field": aws.ToString(ps.Field)})
		}
		cfg["ordered_placement_strategy"] = pss
	}
	if len(s.ServiceRegistries) > 0 {
		var srs []any
		for _, sr := range s.ServiceRegistries {
			m := map[string]any{"registry_arn": aws.ToString(sr.RegistryArn)}
			if v := aws.ToString(sr.ContainerName); v != "" {
				m["container_name"] = v
			}
			if sr.ContainerPort != nil {
				m["container_port"] = *sr.ContainerPort
			}
			if sr.Port != nil {
				m["port"] = *sr.Port
			}
			srs = append(srs, m)
		}
		cfg["service_registries"] = srs
	}
	// ServiceConnectConfiguration isn't on the top-level Service object at
	// all -- only on its currently active (PRIMARY) deployment.
	for _, dep := range s.Deployments {
		if aws.ToString(dep.Status) != "PRIMARY" || dep.ServiceConnectConfiguration == nil {
			continue
		}
		scc := dep.ServiceConnectConfiguration
		if scc.Enabled {
			m := map[string]any{"enabled": true}
			if v := aws.ToString(scc.Namespace); v != "" {
				m["namespace"] = v
			}
			cfg["service_connect_configuration"] = m
		}
		break
	}
	return cfg, nil
}

func hydrateTaskDef(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ecs.NewFromConfig(c.Cfg(r.Region)).DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &r.ARN})
	if err != nil {
		return nil, err
	}
	td := out.TaskDefinition
	// every deploy registers a new revision and deregisters the last one;
	// DescribeTaskDefinition (and the tagging API sweep that discovers
	// these in the first place) happily returns INACTIVE revisions, but
	// the provider's import path treats anything but the current ACTIVE
	// revision as a nonexistent remote object. Not worth managing a
	// deregistered revision as IaC anyway, so drop it the same way
	// hydrateKMSKey drops an AWS-managed key: an error here just excludes
	// the resource from the output.
	if td.Status != ecstypes.TaskDefinitionStatusActive {
		return nil, fmt.Errorf("task definition revision is %s, not the active one", td.Status)
	}
	cd, err := json.Marshal(td.ContainerDefinitions)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"family":                aws.ToString(td.Family),
		"container_definitions": string(cd),
	}
	if len(td.RequiresCompatibilities) > 0 {
		var rc []any
		for _, x := range td.RequiresCompatibilities {
			rc = append(rc, string(x))
		}
		cfg["requires_compatibilities"] = rc
	}
	if v := string(td.NetworkMode); v != "" {
		cfg["network_mode"] = v
	}
	if v := aws.ToString(td.Cpu); v != "" {
		cfg["cpu"] = v
	}
	if v := aws.ToString(td.Memory); v != "" {
		cfg["memory"] = v
	}
	if v := aws.ToString(td.ExecutionRoleArn); v != "" {
		cfg["execution_role_arn"] = v
	}
	if v := aws.ToString(td.TaskRoleArn); v != "" {
		cfg["task_role_arn"] = v
	}
	return cfg, nil
}

func hydrateECSCapacityProvider(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := ecs.NewFromConfig(c.Cfg(r.Region)).DescribeCapacityProviders(ctx, &ecs.DescribeCapacityProvidersInput{
		CapacityProviders: []string{name},
	})
	if err != nil {
		return nil, err
	}
	if len(out.CapacityProviders) == 0 {
		return nil, fmt.Errorf("not found")
	}
	p := out.CapacityProviders[0]
	if strings.HasPrefix(aws.ToString(p.Name), "FARGATE") {
		return nil, fmt.Errorf("AWS-managed capacity provider")
	}
	cfg := map[string]any{"name": aws.ToString(p.Name)}
	if a := p.AutoScalingGroupProvider; a != nil {
		asg := map[string]any{"auto_scaling_group_arn": aws.ToString(a.AutoScalingGroupArn)}
		if v := string(a.ManagedTerminationProtection); v != "" {
			asg["managed_termination_protection"] = v
		}
		if m := a.ManagedScaling; m != nil {
			ms := map[string]any{"status": string(m.Status)}
			if m.TargetCapacity != nil {
				ms["target_capacity"] = *m.TargetCapacity
			}
			if m.MinimumScalingStepSize != nil {
				ms["minimum_scaling_step_size"] = *m.MinimumScalingStepSize
			}
			if m.MaximumScalingStepSize != nil {
				ms["maximum_scaling_step_size"] = *m.MaximumScalingStepSize
			}
			asg["managed_scaling"] = ms
		}
		cfg["auto_scaling_group_provider"] = asg
	}
	// managed_instances_provider's own nested shape (instance_launch_template,
	// network/storage/capacity-reservation config, instance_requirements'
	// ~20 attribute-based-selection fields) maps onto the schema almost
	// entirely by name -- Generic() handles the whole tree once the
	// VCpu/MiB/GiB acronym fix (nameconv.tokenFix) is in place, so no
	// hand-built path is needed here the way auto_scaling_group_provider
	// above has one.
	if p.ManagedInstancesProvider != nil {
		if mipSch, serr := schemaFor("aws_ecs_capacity_provider"); serr == nil {
			if nb, ok := mipSch.NestedBlock("managed_instances_provider"); ok {
				if mip, gerr := Generic(p.ManagedInstancesProvider, nb.Block, nil); gerr == nil && len(mip) > 0 {
					cfg["managed_instances_provider"] = []any{mip}
				}
			}
		}
	}
	return cfg, nil
}

func hydrateEKS(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := eks.NewFromConfig(c.Cfg(r.Region)).DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cl := out.Cluster
	cfg := map[string]any{
		"name":     aws.ToString(cl.Name),
		"role_arn": aws.ToString(cl.RoleArn),
	}
	if v := aws.ToString(cl.Version); v != "" {
		cfg["version"] = v
	}
	if cl.ResourcesVpcConfig != nil {
		vpc := cl.ResourcesVpcConfig
		vc := map[string]any{}
		if len(vpc.SubnetIds) > 0 {
			vc["subnet_ids"] = toAny(vpc.SubnetIds)
		}
		if len(vpc.SecurityGroupIds) > 0 {
			vc["security_group_ids"] = toAny(vpc.SecurityGroupIds)
		}
		vc["endpoint_public_access"] = vpc.EndpointPublicAccess
		vc["endpoint_private_access"] = vpc.EndpointPrivateAccess
		// AWS's own default (0.0.0.0/0, plus ::/0 for dual-stack) is what a
		// cluster with no real restriction returns -- only setting it when
		// genuinely present avoids a spurious diff for the common case,
		// while still correctly capturing a locked-down production cluster
		// that restricts API server access.
		if len(vpc.PublicAccessCidrs) > 0 {
			vc["public_access_cidrs"] = toAny(vpc.PublicAccessCidrs)
		}
		cfg["vpc_config"] = vc
	}
	// encryption_config (KMS-encrypted Kubernetes secrets) is common on any
	// production cluster -- DescribeCluster returns it directly, no extra
	// call needed.
	if len(cl.EncryptionConfig) > 0 {
		var ec []any
		for _, e := range cl.EncryptionConfig {
			m := map[string]any{}
			if len(e.Resources) > 0 {
				m["resources"] = toAny(e.Resources)
			}
			if e.Provider != nil {
				m["provider"] = map[string]any{"key_arn": aws.ToString(e.Provider.KeyArn)}
			}
			ec = append(ec, m)
		}
		cfg["encryption_config"] = ec
	}
	if nc := cl.KubernetesNetworkConfig; nc != nil {
		knc := map[string]any{}
		if v := string(nc.IpFamily); v != "" {
			knc["ip_family"] = v
		}
		if v := aws.ToString(nc.ServiceIpv4Cidr); v != "" {
			knc["service_ipv4_cidr"] = v
		}
		if len(knc) > 0 {
			cfg["kubernetes_network_config"] = knc
		}
	}
	return cfg, nil
}

// hydrateECRRepo: the SDK's RepositoryName field doesn't snake-case to the
// schema's Required "name" attribute -- Generic() alone silently produced
// config missing a Required attribute for every repository (would fail
// `tofu validate` outright, "name is required").
func hydrateECRRepo(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_ecr_repository")
	if err != nil {
		return nil, err
	}
	name := r.ID
	out, err := ecr.NewFromConfig(c.Cfg(r.Region)).DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{RepositoryNames: []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.Repositories) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return Generic(out.Repositories[0], sch, map[string]string{"repository_name": "name"})
}
