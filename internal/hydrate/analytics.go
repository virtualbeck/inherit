package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/mwaa"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_glue_job", hydrateGlueJob)
	register("aws_glue_crawler", hydrateGlueCrawler)
	register("aws_glue_catalog_database", hydrateGlueDB)
	register("aws_athena_workgroup", hydrateAthenaWG)
	register("aws_opensearch_domain", hydrateOpenSearch)
	register("aws_sagemaker_notebook_instance", hydrateSagemakerNotebook)
	register("aws_mwaa_environment", hydrateMWAAEnvironment)
}

func hydrateGlueJob(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetJob(ctx, &glue.GetJobInput{JobName: &name})
	if err != nil {
		return nil, err
	}
	j := out.Job
	cfg := map[string]any{
		"name":     aws.ToString(j.Name),
		"role_arn": aws.ToString(j.Role),
	}
	if v := aws.ToString(j.GlueVersion); v != "" {
		cfg["glue_version"] = v
	}
	if j.MaxRetries != 0 {
		cfg["max_retries"] = j.MaxRetries
	}
	if j.Timeout != nil {
		cfg["timeout"] = *j.Timeout
	}
	if j.NumberOfWorkers != nil {
		cfg["number_of_workers"] = *j.NumberOfWorkers
	}
	if v := string(j.WorkerType); v != "" {
		cfg["worker_type"] = v
	}
	if j.Command != nil {
		cmd := map[string]any{}
		if v := aws.ToString(j.Command.Name); v != "" {
			cmd["name"] = v
		}
		if v := aws.ToString(j.Command.ScriptLocation); v != "" {
			cmd["script_location"] = v
		}
		if v := aws.ToString(j.Command.PythonVersion); v != "" {
			cmd["python_version"] = v
		}
		cfg["command"] = cmd
	}
	if len(j.DefaultArguments) > 0 {
		m := map[string]any{}
		for k, v := range j.DefaultArguments {
			m[k] = v
		}
		cfg["default_arguments"] = m
	}
	return cfg, nil
}

func hydrateGlueCrawler(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetCrawler(ctx, &glue.GetCrawlerInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cr := out.Crawler
	cfg := map[string]any{
		"name":          aws.ToString(cr.Name),
		"role":          aws.ToString(cr.Role),
		"database_name": aws.ToString(cr.DatabaseName),
	}
	if v := aws.ToString(cr.TablePrefix); v != "" {
		cfg["table_prefix"] = v
	}
	if cr.Schedule != nil {
		if v := aws.ToString(cr.Schedule.ScheduleExpression); v != "" {
			cfg["schedule"] = v
		}
	}
	if cr.Targets != nil {
		var s3 []any
		for _, t := range cr.Targets.S3Targets {
			tg := map[string]any{"path": aws.ToString(t.Path)}
			if len(t.Exclusions) > 0 {
				tg["exclusions"] = toAny(t.Exclusions)
			}
			s3 = append(s3, tg)
		}
		if len(s3) > 0 {
			cfg["s3_target"] = s3
		}
	}
	return cfg, nil
}

func hydrateGlueDB(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID // glue database ARN resource is "database/<name>"
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := glue.NewFromConfig(c.Cfg(r.Region)).GetDatabase(ctx, &glue.GetDatabaseInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Database.Name)}
	if d := aws.ToString(out.Database.Description); d != "" {
		cfg["description"] = d
	}
	if l := aws.ToString(out.Database.LocationUri); l != "" {
		cfg["location_uri"] = l
	}
	return cfg, nil
}

// hydrateAthenaWG needs overrides: the SDK's EnforceWorkGroupConfiguration /
// PublishCloudWatchMetricsEnabled mechanically snake-case to
// "enforce_work_group_configuration" / "publish_cloud_watch_metrics_enabled"
// ("WorkGroup"/"CloudWatch" as two words), one underscore short of the
// schema's "enforce_workgroup_configuration" / "publish_cloudwatch_metrics_enabled"
// (one word each). overrides applies at every nesting depth, so both work
// from the same top-level call.
func hydrateAthenaWG(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_athena_workgroup")
	if err != nil {
		return nil, err
	}
	out, err := athena.NewFromConfig(c.Cfg(r.Region)).GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: &r.ID})
	if err != nil {
		return nil, err
	}
	return Generic(out.WorkGroup, sch, map[string]string{
		"enforce_work_group_configuration":    "enforce_workgroup_configuration",
		"publish_cloud_watch_metrics_enabled": "publish_cloudwatch_metrics_enabled",
	})
}

func hydrateOpenSearch(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID // es domain ARN resource is "domain/<name>"
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := opensearch.NewFromConfig(c.Cfg(r.Region)).DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &name})
	if err != nil {
		return nil, err
	}
	d := out.DomainStatus
	cfg := map[string]any{"domain_name": aws.ToString(d.DomainName)}
	if v := aws.ToString(d.EngineVersion); v != "" {
		cfg["engine_version"] = v
	}
	if cc0 := d.ClusterConfig; cc0 != nil {
		cc := map[string]any{}
		if v := string(cc0.InstanceType); v != "" {
			cc["instance_type"] = v
		}
		if cc0.InstanceCount != nil {
			cc["instance_count"] = *cc0.InstanceCount
		}
		if cc0.ZoneAwarenessEnabled != nil {
			cc["zone_awareness_enabled"] = *cc0.ZoneAwarenessEnabled
		}
		if aws.ToBool(cc0.DedicatedMasterEnabled) {
			cc["dedicated_master_enabled"] = true
			if cc0.DedicatedMasterCount != nil {
				cc["dedicated_master_count"] = *cc0.DedicatedMasterCount
			}
			if v := string(cc0.DedicatedMasterType); v != "" {
				cc["dedicated_master_type"] = v
			}
		}
		if aws.ToBool(cc0.WarmEnabled) {
			cc["warm_enabled"] = true
			if cc0.WarmCount != nil {
				cc["warm_count"] = *cc0.WarmCount
			}
			if v := string(cc0.WarmType); v != "" {
				cc["warm_type"] = v
			}
		}
		if zac := cc0.ZoneAwarenessConfig; zac != nil && zac.AvailabilityZoneCount != nil {
			cc["zone_awareness_config"] = map[string]any{"availability_zone_count": *zac.AvailabilityZoneCount}
		}
		cfg["cluster_config"] = cc
	}
	if eb := d.EBSOptions; eb != nil && aws.ToBool(eb.EBSEnabled) {
		ebs := map[string]any{
			"ebs_enabled": true,
			"volume_size": aws.ToInt32(eb.VolumeSize),
			"volume_type": string(eb.VolumeType),
		}
		// only gp3/provisioned-iops volumes carry these; AWS returns 0 for
		// volume types that don't support them.
		if eb.Iops != nil && *eb.Iops > 0 {
			ebs["iops"] = *eb.Iops
		}
		if eb.Throughput != nil && *eb.Throughput > 0 {
			ebs["throughput"] = *eb.Throughput
		}
		cfg["ebs_options"] = ebs
	}
	if e := d.EncryptionAtRestOptions; e != nil && aws.ToBool(e.Enabled) {
		ear := map[string]any{"enabled": true}
		if v := aws.ToString(e.KmsKeyId); v != "" {
			ear["kms_key_id"] = v
		}
		cfg["encrypt_at_rest"] = ear
	}
	if n := d.NodeToNodeEncryptionOptions; n != nil && n.Enabled != nil {
		cfg["node_to_node_encryption"] = map[string]any{"enabled": *n.Enabled}
	}
	if deo := d.DomainEndpointOptions; deo != nil {
		m := map[string]any{}
		if deo.EnforceHTTPS != nil {
			m["enforce_https"] = *deo.EnforceHTTPS
		}
		if v := string(deo.TLSSecurityPolicy); v != "" {
			m["tls_security_policy"] = v
		}
		if aws.ToBool(deo.CustomEndpointEnabled) {
			m["custom_endpoint_enabled"] = true
			if v := aws.ToString(deo.CustomEndpoint); v != "" {
				m["custom_endpoint"] = v
			}
			if v := aws.ToString(deo.CustomEndpointCertificateArn); v != "" {
				m["custom_endpoint_certificate_arn"] = v
			}
		}
		if len(m) > 0 {
			cfg["domain_endpoint_options"] = m
		}
	}
	if aso := d.AdvancedSecurityOptions; aso != nil && aws.ToBool(aso.Enabled) {
		m := map[string]any{"enabled": true}
		if aso.AnonymousAuthEnabled != nil {
			m["anonymous_auth_enabled"] = *aso.AnonymousAuthEnabled
		}
		if aso.InternalUserDatabaseEnabled != nil {
			m["internal_user_database_enabled"] = *aso.InternalUserDatabaseEnabled
		}
		// master_user_options (the admin username/password or IAM ARN) is
		// never returned by DescribeDomain -- no AWS-side data at all.
		cfg["advanced_security_options"] = m
	}
	if vpc := d.VPCOptions; vpc != nil {
		m := map[string]any{}
		if len(vpc.SubnetIds) > 0 {
			m["subnet_ids"] = toAny(vpc.SubnetIds)
		}
		if len(vpc.SecurityGroupIds) > 0 {
			m["security_group_ids"] = toAny(vpc.SecurityGroupIds)
		}
		if len(m) > 0 {
			cfg["vpc_options"] = m
		}
	}
	return cfg, nil
}

func hydrateSagemakerNotebook(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := sagemaker.NewFromConfig(c.Cfg(r.Region)).DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":          aws.ToString(out.NotebookInstanceName),
		"instance_type": string(out.InstanceType),
		"role_arn":      aws.ToString(out.RoleArn),
	}
	if v := aws.ToString(out.SubnetId); v != "" {
		cfg["subnet_id"] = v
	}
	if len(out.SecurityGroups) > 0 {
		cfg["security_groups"] = toAny(out.SecurityGroups)
	}
	if v := aws.ToString(out.KmsKeyId); v != "" {
		cfg["kms_key_id"] = v
	}
	if out.VolumeSizeInGB != nil {
		cfg["volume_size"] = *out.VolumeSizeInGB
	}
	if v := string(out.DirectInternetAccess); v != "" {
		cfg["direct_internet_access"] = v
	}
	return cfg, nil
}

func hydrateMWAAEnvironment(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_mwaa_environment")
	if err != nil {
		return nil, err
	}
	name := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok {
		name = rest
	}
	out, err := mwaa.NewFromConfig(c.Cfg(r.Region)).GetEnvironment(ctx, &mwaa.GetEnvironmentInput{Name: &name})
	if err != nil {
		return nil, err
	}
	e := out.Environment
	if e == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg, err := Generic(e, sch, nil)
	if err != nil {
		return nil, err
	}
	// airflow_configuration_options can carry sensitive values (DB
	// connection strings, secrets) -- deliberately never written into
	// generated config.
	delete(cfg, "airflow_configuration_options")
	return cfg, nil
}
