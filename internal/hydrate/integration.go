package hydrate

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	rex "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_sfn_state_machine", genericHydrator("aws_sfn_state_machine", fetchSFN))
	register("aws_sfn_activity", genericHydrator("aws_sfn_activity", fetchSFNActivity))
	register("aws_appsync_graphql_api", hydrateAppSync)
	register("aws_transfer_server", genericHydrator("aws_transfer_server", fetchTransfer))
	register("aws_codebuild_project", hydrateCodeBuild)
	register("aws_codepipeline", hydrateCodePipeline)
	register("aws_datasync_task", hydrateDataSyncTask)
	register("aws_datasync_agent", hydrateDataSyncAgent)
	register("aws_datasync_location_s3", hydrateDataSyncLocation)
	register("aws_ssm_association", hydrateSSMAssociation)
	register("aws_cloudformation_stack", hydrateCloudFormationStack)
	register("aws_cloudformation_stack_set", hydrateCloudFormationStackSet)
	register("aws_ssm_parameter", hydrateSSMParameter)
	register("aws_cognito_user_pool", hydrateCognitoPool)
	register("aws_ssm_maintenance_window", hydrateMaintenanceWindow)
	register("aws_ssm_patch_baseline", hydratePatchBaseline)
	register("aws_ssm_document", hydrateSSMDocument)
	register("aws_appconfig_application", hydrateAppConfigApplication)
	register("aws_appconfig_deployment_strategy", hydrateAppConfigDeploymentStrategy)
	register("aws_service_discovery_service", hydrateSDService)
	register("aws_cognito_identity_pool", hydrateCognitoIdentityPool)
	register("aws_resourceexplorer2_index", hydrateResourceExplorerIndex)
	register("aws_resourceexplorer2_view", hydrateResourceExplorerView)
	register("aws_sesv2_email_identity", hydrateSESv2Identity)
	register("aws_sesv2_configuration_set", hydrateSESv2ConfigSet)
	register("aws_sesv2_dedicated_ip_pool", genericHydrator("aws_sesv2_dedicated_ip_pool", fetchSESv2DedicatedIPPool))
}

func fetchSESv2DedicatedIPPool(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	out, err := sesv2.NewFromConfig(c.Cfg(r.Region)).GetDedicatedIpPool(ctx, &sesv2.GetDedicatedIpPoolInput{PoolName: &name})
	if err != nil {
		return nil, err
	}
	return out.DedicatedIpPool, nil
}

func fetchSFN(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := sfn.NewFromConfig(c.Cfg(r.Region)).DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func fetchSFNActivity(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := sfn.NewFromConfig(c.Cfg(r.Region)).DescribeActivity(ctx, &sfn.DescribeActivityInput{ActivityArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hydrateAppSync(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID // appsync ARN resource is "apis/<id>"; API id needed
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := appsync.NewFromConfig(c.Cfg(r.Region)).GetGraphqlApi(ctx, &appsync.GetGraphqlApiInput{ApiId: &name})
	if err != nil {
		return nil, err
	}
	a := out.GraphqlApi
	cfg := map[string]any{
		"name":                aws.ToString(a.Name),
		"authentication_type": string(a.AuthenticationType),
	}
	if v := string(a.Visibility); v != "" && v != "GLOBAL" {
		cfg["visibility"] = v
	}
	if a.XrayEnabled {
		cfg["xray_enabled"] = true
	}
	// log_config/user_pool_config were dropped entirely before --
	// CloudWatch logging is routine on a real API, and an API using Cognito
	// user pool auth (AuthenticationType == AMAZON_COGNITO_USER_POOLS) has
	// nothing else recoverable at all without user_pool_config. schema
	// itself isn't fetched: GetIntrospectionSchema returns a derived SDL/
	// JSON representation, not what was submitted, and the provider's own
	// Read doesn't populate it either -- same shape as the documented
	// no-Read-equivalent directive attributes.
	if lc := a.LogConfig; lc != nil {
		m := map[string]any{"cloudwatch_logs_role_arn": aws.ToString(lc.CloudWatchLogsRoleArn)}
		if v := string(lc.FieldLogLevel); v != "" {
			m["field_log_level"] = v
		}
		if lc.ExcludeVerboseContent {
			m["exclude_verbose_content"] = true
		}
		cfg["log_config"] = m
	}
	if up := a.UserPoolConfig; up != nil {
		m := map[string]any{
			"aws_region":     aws.ToString(up.AwsRegion),
			"user_pool_id":   aws.ToString(up.UserPoolId),
			"default_action": string(up.DefaultAction),
		}
		if v := aws.ToString(up.AppIdClientRegex); v != "" {
			m["app_id_client_regex"] = v
		}
		cfg["user_pool_config"] = m
	}
	return cfg, nil
}

func fetchTransfer(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeServer(ctx, &transfer.DescribeServerInput{ServerId: &r.ID})
	if err != nil {
		return nil, err
	}
	return out.Server, nil
}

// hydrateCodeBuild was a bare genericHydrator until this audit found it
// silently dropping: build_timeout / queued_timeout (SDK's
// TimeoutInMinutes / QueuedTimeoutInMinutes don't mechanically snake-case
// to either schema name), and badge_enabled / badge_url entirely (the
// schema has them as flat scalars, but the SDK returns a nested *ProjectBadge
// struct under a key ("badge") the schema doesn't even have).
func hydrateCodeBuild(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_codebuild_project")
	if err != nil {
		return nil, err
	}
	out, err := codebuild.NewFromConfig(c.Cfg(r.Region)).BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.Projects) == 0 {
		return nil, fmt.Errorf("not found")
	}
	p := out.Projects[0]

	cfg, err := Generic(p, sch, map[string]string{
		"timeout_in_minutes":        "build_timeout",
		"queued_timeout_in_minutes": "queued_timeout",
	})
	if err != nil {
		return nil, err
	}
	if p.Badge != nil {
		cfg["badge_enabled"] = p.Badge.BadgeEnabled
		if v := aws.ToString(p.Badge.BadgeRequestUrl); v != "" {
			cfg["badge_url"] = v
		}
	}
	return cfg, nil
}

func hydrateCodePipeline(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := codepipeline.NewFromConfig(c.Cfg(r.Region)).GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: &name})
	if err != nil {
		return nil, err
	}
	p := out.Pipeline
	cfg := map[string]any{
		"name":     aws.ToString(p.Name),
		"role_arn": aws.ToString(p.RoleArn),
	}
	if v := string(p.PipelineType); v != "" {
		cfg["pipeline_type"] = v
	}
	if v := string(p.ExecutionMode); v != "" {
		cfg["execution_mode"] = v
	}
	if p.ArtifactStore != nil {
		as := map[string]any{"type": string(p.ArtifactStore.Type)}
		if v := aws.ToString(p.ArtifactStore.Location); v != "" {
			as["location"] = v
		}
		cfg["artifact_store"] = as
	}
	var stages []any
	for _, s := range p.Stages {
		st := map[string]any{"name": aws.ToString(s.Name)}
		var acts []any
		for _, a := range s.Actions {
			act := map[string]any{"name": aws.ToString(a.Name)}
			if a.ActionTypeId != nil {
				act["category"] = string(a.ActionTypeId.Category)
				act["owner"] = string(a.ActionTypeId.Owner)
				act["provider"] = aws.ToString(a.ActionTypeId.Provider)
				act["version"] = aws.ToString(a.ActionTypeId.Version)
			}
			if len(a.Configuration) > 0 {
				m := map[string]any{}
				for k, v := range a.Configuration {
					m[k] = v
				}
				act["configuration"] = m
			}
			if len(a.InputArtifacts) > 0 {
				var ins []any
				for _, ia := range a.InputArtifacts {
					ins = append(ins, aws.ToString(ia.Name))
				}
				act["input_artifacts"] = ins
			}
			if len(a.OutputArtifacts) > 0 {
				var outs []any
				for _, oa := range a.OutputArtifacts {
					outs = append(outs, aws.ToString(oa.Name))
				}
				act["output_artifacts"] = outs
			}
			if v := aws.ToString(a.RoleArn); v != "" {
				act["role_arn"] = v
			}
			if v := aws.ToString(a.Region); v != "" {
				act["region"] = v
			}
			if v := aws.ToString(a.Namespace); v != "" {
				act["namespace"] = v
			}
			if a.RunOrder != nil {
				act["run_order"] = *a.RunOrder
			}
			acts = append(acts, act)
		}
		st["action"] = acts
		stages = append(stages, st)
	}
	cfg["stage"] = stages
	return cfg, nil
}

// hydrateDataSyncAgent is hand-built rather than Generic(): PrivateLinkConfig's
// fields (private_link_endpoint/security_group_arns/subnet_arns/
// vpc_endpoint_id) are flat top-level schema attributes, not nested under a
// "private_link_config" block, so Generic()'s straight JSON round-trip
// would produce a nested object the schema has no block for at all
// (dropped silently) instead of flattening it.
func hydrateDataSyncAgent(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := datasync.NewFromConfig(c.Cfg(r.Region)).DescribeAgent(ctx, &datasync.DescribeAgentInput{AgentArn: &arn})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if v := aws.ToString(out.Name); v != "" {
		cfg["name"] = v
	}
	if pl := out.PrivateLinkConfig; pl != nil {
		if v := aws.ToString(pl.PrivateLinkEndpoint); v != "" {
			cfg["private_link_endpoint"] = v
		}
		if len(pl.SecurityGroupArns) > 0 {
			cfg["security_group_arns"] = toAny(pl.SecurityGroupArns)
		}
		if len(pl.SubnetArns) > 0 {
			cfg["subnet_arns"] = toAny(pl.SubnetArns)
		}
		if v := aws.ToString(pl.VpcEndpointId); v != "" {
			cfg["vpc_endpoint_id"] = v
		}
	}
	return cfg, nil
}

func hydrateDataSyncTask(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := datasync.NewFromConfig(c.Cfg(r.Region)).DescribeTask(ctx, &datasync.DescribeTaskInput{TaskArn: &arn})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"source_location_arn":      aws.ToString(out.SourceLocationArn),
		"destination_location_arn": aws.ToString(out.DestinationLocationArn),
	}
	if v := aws.ToString(out.Name); v != "" {
		cfg["name"] = v
	}
	if v := aws.ToString(out.CloudWatchLogGroupArn); v != "" {
		cfg["cloudwatch_log_group_arn"] = v
	}
	return cfg, nil
}

// datasyncS3BucketARNAndSubdir splits a DataSync S3 location's LocationUri
// ("s3://bucket-name/some/subdirectory") into the schema's separate
// s3_bucket_arn and (Required) subdirectory attributes -- DescribeLocationS3
// never returns either field directly; the real provider's Read does this
// same parsing (terraform-provider-aws's datasync/uri.go). Only the common
// case (a plain bucket name) is handled; an S3-on-Outposts access point
// location needs the ARN-aware branch the provider has and isn't handled
// here, unconfirmed against any real account.
func datasyncS3BucketARNAndSubdir(uri string) (bucketARN, subdir string, ok bool) {
	const prefix = "s3://"
	if !strings.HasPrefix(uri, prefix) {
		return "", "", false
	}
	rest := uri[len(prefix):]
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return "", "", false
	}
	bucket := rest[:i]
	// emit's own ARN parameterization rewrites any "arn:<partition>:..."
	// literal's partition segment to a data-source lookup regardless of
	// what's written here, so a literal "aws" is correct in every partition.
	return "arn:aws:s3:::" + bucket, rest[i:], true
}

func hydrateDataSyncLocationS3(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := datasync.NewFromConfig(c.Cfg(r.Region)).DescribeLocationS3(ctx, &datasync.DescribeLocationS3Input{LocationArn: &arn})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if bucketARN, subdir, ok := datasyncS3BucketARNAndSubdir(aws.ToString(out.LocationUri)); ok {
		cfg["s3_bucket_arn"] = bucketARN
		cfg["subdirectory"] = subdir
	}
	if v := string(out.S3StorageClass); v != "" {
		cfg["s3_storage_class"] = v
	}
	if out.S3Config != nil {
		cfg["s3_config"] = map[string]any{"bucket_access_role_arn": aws.ToString(out.S3Config.BucketAccessRoleArn)}
	}
	return cfg, nil
}

func hydrateSSMAssociation(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ssm.NewFromConfig(c.Cfg(r.Region)).DescribeAssociation(ctx, &ssm.DescribeAssociationInput{AssociationId: &id})
	if err != nil {
		return nil, err
	}
	a := out.AssociationDescription
	if a == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"name": aws.ToString(a.Name)}
	if v := aws.ToString(a.AssociationName); v != "" {
		cfg["association_name"] = v
	}
	if v := aws.ToString(a.ScheduleExpression); v != "" {
		cfg["schedule_expression"] = v
	}
	if v := aws.ToString(a.DocumentVersion); v != "" {
		cfg["document_version"] = v
	}
	if len(a.Parameters) > 0 {
		// the API returns each value as a list; the provider's `parameters` is
		// map(string), so collapse single-element lists and comma-join the rest.
		m := map[string]any{}
		for k, v := range a.Parameters {
			switch len(v) {
			case 0:
			case 1:
				m[k] = v[0]
			default:
				m[k] = strings.Join(v, ",")
			}
		}
		if len(m) > 0 {
			cfg["parameters"] = m
		}
	}
	var targets []any
	for _, t := range a.Targets {
		targets = append(targets, map[string]any{
			"key":    aws.ToString(t.Key),
			"values": toAny(t.Values),
		})
	}
	if len(targets) > 0 {
		cfg["targets"] = targets
	}
	// ApplyOnlyAtCronInterval / ComplianceSeverity are real, non-zero-value
	// settings on the association; leaving them out lets the provider default
	// (false / "UNSPECIFIED") clobber what's actually configured.
	cfg["apply_only_at_cron_interval"] = a.ApplyOnlyAtCronInterval
	if v := string(a.ComplianceSeverity); v != "" {
		cfg["compliance_severity"] = v
	}
	if v := string(a.SyncCompliance); v != "" {
		cfg["sync_compliance"] = v
	}
	if v := aws.ToString(a.MaxConcurrency); v != "" {
		cfg["max_concurrency"] = v
	}
	if v := aws.ToString(a.MaxErrors); v != "" {
		cfg["max_errors"] = v
	}
	if v := aws.ToString(a.AutomationTargetParameterName); v != "" {
		cfg["automation_target_parameter_name"] = v
	}
	if len(a.CalendarNames) > 0 {
		cfg["calendar_names"] = toAny(a.CalendarNames)
	}
	if a.OutputLocation != nil && a.OutputLocation.S3Location != nil {
		s3 := a.OutputLocation.S3Location
		if bucket := aws.ToString(s3.OutputS3BucketName); bucket != "" {
			loc := map[string]any{"s3_bucket_name": bucket}
			if v := aws.ToString(s3.OutputS3KeyPrefix); v != "" {
				loc["s3_key_prefix"] = v
			}
			if v := aws.ToString(s3.OutputS3Region); v != "" {
				loc["s3_region"] = v
			}
			cfg["output_location"] = loc
		}
	}
	return cfg, nil
}

func hydrateCloudFormationStack(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := cloudformation.NewFromConfig(c.Cfg(r.Region))
	name := r.ID
	if n, _, ok := strings.Cut(r.ID, "/"); ok { // ARN id is "name/uuid"
		name = n
	}
	out, err := cl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.Stacks) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.Stacks[0]
	// StackSet instances and nested stacks are managed by their StackSet / parent;
	// adopting them into Terraform fights the managing service.
	if strings.HasPrefix(name, "StackSet-") || s.ParentId != nil || s.RootId != nil {
		return nil, fmt.Errorf("StackSet / nested stack (managed elsewhere)")
	}
	cfg := map[string]any{"name": aws.ToString(s.StackName)}
	if len(s.Capabilities) > 0 {
		var caps []any
		for _, x := range s.Capabilities {
			caps = append(caps, string(x))
		}
		cfg["capabilities"] = caps
	}
	if len(s.Parameters) > 0 {
		m := map[string]any{}
		for _, p := range s.Parameters {
			m[aws.ToString(p.ParameterKey)] = aws.ToString(p.ParameterValue)
		}
		cfg["parameters"] = m
	}
	if len(s.NotificationARNs) > 0 {
		cfg["notification_arns"] = toAny(s.NotificationARNs)
	}
	if v := aws.ToString(s.RoleARN); v != "" {
		cfg["iam_role_arn"] = v
	}
	if tb, err := cl.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: &name}); err == nil {
		if body := aws.ToString(tb.TemplateBody); body != "" {
			cfg["template_body"] = body
		}
	}
	return cfg, nil
}

func hydrateSSMParameter(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := ssm.NewFromConfig(c.Cfg(r.Region))
	// The ARN's resource segment ("parameter/tf/route53/baseline/zone_id")
	// never carries a hierarchical parameter's real leading "/" -- AWS's own
	// convention for embedding a path in an ARN -- so r.ID is missing it for
	// any hierarchical parameter. Fetching (or importing) with that name
	// as-is 400s. Try as discovered first, then with a leading slash added.
	// GetParameter without WithDecryption is safe to call regardless of
	// type: for a SecureString it returns the ciphertext, never plaintext.
	name := r.ID
	gp, err := cl.GetParameter(ctx, &ssm.GetParameterInput{Name: &name})
	if err != nil && !strings.HasPrefix(r.ID, "/") {
		name = "/" + r.ID
		gp, err = cl.GetParameter(ctx, &ssm.GetParameterInput{Name: &name})
	}
	if err != nil {
		return nil, err
	}
	if gp.Parameter == nil {
		return nil, fmt.Errorf("parameter %s: empty response", r.ID)
	}
	p := gp.Parameter
	realName := aws.ToString(p.Name)
	cfg := map[string]any{"name": realName, "type": string(p.Type)}

	// GetParameter doesn't return Description/Tier; a name-filtered
	// DescribeParameters picks them up without listing every parameter in
	// the account (the previous, unpaginated "list everything and find a
	// match" approach silently missed any parameter past the first page).
	if dp, err := cl.DescribeParameters(ctx, &ssm.DescribeParametersInput{
		ParameterFilters: []ssmtypes.ParameterStringFilter{
			{Key: aws.String("Name"), Option: aws.String("Equals"), Values: []string{realName}},
		},
	}); err == nil && len(dp.Parameters) > 0 {
		meta := dp.Parameters[0]
		if d := aws.ToString(meta.Description); d != "" {
			cfg["description"] = d
		}
		if t := string(meta.Tier); t != "" && t != "Standard" {
			cfg["tier"] = t
		}
		// KeyId/DataType/AllowedPattern only come back on DescribeParameters'
		// metadata, never on GetParameter itself -- silently dropped before.
		if k := aws.ToString(meta.KeyId); k != "" && k != "alias/aws/ssm" {
			cfg["key_id"] = k
		}
		if dt := aws.ToString(meta.DataType); dt != "" && dt != "text" {
			cfg["data_type"] = dt
		}
		if ap := aws.ToString(meta.AllowedPattern); ap != "" {
			cfg["allowed_pattern"] = ap
		}
	}

	// the provider requires exactly one of value/insecure_value/value_wo
	// on every aws_ssm_parameter, regardless of type.
	if p.Type == ssmtypes.ParameterTypeSecureString {
		cfg["value"] = ssmSecureValuePlaceholder
	} else {
		cfg["value"] = aws.ToString(p.Value)
	}
	return cfg, nil
}

// ssmSecureValuePlaceholder stands in for a SecureString parameter's value:
// inherit never decrypts secrets (GetParameter with WithDecryption=true would
// still be a read-only call, but writing the plaintext into generated HCL
// and, worse, local state is a data-handling risk this tool doesn't take on
// unasked). The provider requires exactly one of value/insecure_value/
// value_wo regardless -- `value` is used (not `insecure_value`) because the
// provider marks it sensitive and redacts it from plan/console output even
// though it's just this placeholder.
const ssmSecureValuePlaceholder = "REPLACE_ME (inherit does not read SecureString values)"

func hydrateCognitoPool(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := cognitoidentityprovider.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: &r.ID})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_cognito_user_pool")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.UserPool, sch, nil)
	if err != nil {
		return nil, err
	}
	p := out.UserPool

	// Generic()'s filterNested drops a whole nested block if any one
	// Required sub-attribute doesn't survive pruning -- both of these got
	// hit on a real pool (schema entirely empty, email_configuration
	// missing just from_email_address), so build them explicitly instead of
	// trusting Generic() for either.
	if attrs := cognitoSchemaAttrs(p.SchemaAttributes); len(attrs) > 0 {
		cfg["schema"] = attrs
	}

	if e := p.EmailConfiguration; e != nil {
		ec := map[string]any{"email_sending_account": string(e.EmailSendingAccount)}
		if v := aws.ToString(e.From); v != "" {
			ec["from_email_address"] = v
		}
		if v := aws.ToString(e.ReplyToEmailAddress); v != "" {
			ec["reply_to_email_address"] = v
		}
		if v := aws.ToString(e.SourceArn); v != "" {
			ec["source_arn"] = v
		}
		if v := aws.ToString(e.ConfigurationSet); v != "" {
			ec["configuration_set"] = v
		}
		cfg["email_configuration"] = ec
	}

	// TOTP MFA state isn't part of DescribeUserPool at all -- it's a
	// separate call.
	if mfa, merr := cl.GetUserPoolMfaConfig(ctx, &cognitoidentityprovider.GetUserPoolMfaConfigInput{UserPoolId: &r.ID}); merr == nil {
		if st := mfa.SoftwareTokenMfaConfiguration; st != nil {
			cfg["software_token_mfa_configuration"] = map[string]any{"enabled": st.Enabled}
		}
	}
	return cfg, nil
}

func cognitoStrAttr(name string, mutable, required bool, minLen, maxLen string) ciptypes.SchemaAttributeType {
	return ciptypes.SchemaAttributeType{
		AttributeDataType: ciptypes.AttributeDataTypeString, DeveloperOnlyAttribute: aws.Bool(false),
		Mutable: aws.Bool(mutable), Required: aws.Bool(required), Name: aws.String(name),
		StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{MinLength: aws.String(minLen), MaxLength: aws.String(maxLen)},
	}
}

func cognitoBoolAttr(name string, mutable, required bool) ciptypes.SchemaAttributeType {
	return ciptypes.SchemaAttributeType{
		AttributeDataType: ciptypes.AttributeDataTypeBoolean, DeveloperOnlyAttribute: aws.Bool(false),
		Mutable: aws.Bool(mutable), Required: aws.Bool(required), Name: aws.String(name),
	}
}

func cognitoMatchesStandardAttr(a ciptypes.SchemaAttributeType) bool {
	for _, std := range cognitoStandardAttrs {
		if reflect.DeepEqual(a, std) {
			return true
		}
	}
	return false
}

// cognitoSchemaAttrs builds the schema[] block from DescribeUserPool's
// SchemaAttributes. DescribeUserPool returns EVERY attribute, including the
// ~20 built-in standard ones every pool gets automatically -- schema[] is a
// Set block with no Computed fallback, so state (from Read) diffs against
// config unless config declares exactly what Read will persist: custom/
// developer-only attributes always, and a standard-named one only when its
// real shape doesn't exactly match cognitoStandardAttrs (see there). AWS
// prefixes custom/dev names with "custom:"/"dev:"; strip that back off
// since the provider re-derives the prefix from developer_only_attribute.
// The provider also validates every entry's (unprefixed) name against a
// hard 20-char cap regardless of standard/custom; skip those too --
// otherwise unreachable in practice, since every standard name this long
// (phone_number_verified) matches its exact standard shape above and is
// already excluded for that reason.
func cognitoSchemaAttrs(schemaAttrs []ciptypes.SchemaAttributeType) []any {
	var attrs []any
	for _, a := range schemaAttrs {
		name := aws.ToString(a.Name)
		stripped := name
		switch {
		case strings.HasPrefix(name, "custom:"):
			stripped = strings.TrimPrefix(name, "custom:")
		case strings.HasPrefix(name, "dev:"):
			stripped = strings.TrimPrefix(name, "dev:")
		default:
			if cognitoMatchesStandardAttr(a) {
				continue // the provider's own Read excludes this exact shape from state too
			}
		}
		if len(stripped) > 20 {
			continue // provider's name validator rejects this no matter what
		}
		m := map[string]any{
			"name":                     stripped,
			"attribute_data_type":      string(a.AttributeDataType),
			"developer_only_attribute": aws.ToBool(a.DeveloperOnlyAttribute),
			"mutable":                  aws.ToBool(a.Mutable),
			"required":                 aws.ToBool(a.Required),
		}
		if sc := a.StringAttributeConstraints; sc != nil {
			m["string_attribute_constraints"] = map[string]any{
				"min_length": aws.ToString(sc.MinLength),
				"max_length": aws.ToString(sc.MaxLength),
			}
		}
		if nc := a.NumberAttributeConstraints; nc != nil {
			m["number_attribute_constraints"] = map[string]any{
				"min_value": aws.ToString(nc.MinValue),
				"max_value": aws.ToString(nc.MaxValue),
			}
		}
		attrs = append(attrs, m)
	}
	return attrs
}

// cognitoStandardAttrs mirrors terraform-provider-aws's own hardcoded table
// (userPoolSchemaAttributeMatchesStandardAttribute in its cognitoidp
// package, plus its separate "identities" case) verbatim, field for field.
// The provider's Read excludes an attribute from state -- via
// reflect.DeepEqual against exactly this table -- only when it matches one
// of these shapes exactly; declaring a match in our config would therefore
// always be a diff, since it can never appear in state. An attribute whose
// real shape differs even slightly (e.g. Required: true where every entry
// here has false) is NOT filtered by the provider and so must be declared,
// with its real observed values, to match what Read actually persists.
// Confirmed against a real pool: family_name/given_name came back
// Required: true (unlike every other standard attribute here, which was
// Required: false and so correctly absent from state).
var cognitoStandardAttrs = []ciptypes.SchemaAttributeType{
	cognitoStrAttr("address", true, false, "0", "2048"),
	cognitoStrAttr("birthdate", true, false, "10", "10"),
	cognitoStrAttr("email", true, false, "0", "2048"),
	cognitoBoolAttr("email_verified", true, false),
	cognitoStrAttr("family_name", true, false, "0", "2048"),
	cognitoStrAttr("gender", true, false, "0", "2048"),
	cognitoStrAttr("given_name", true, false, "0", "2048"),
	{
		AttributeDataType: ciptypes.AttributeDataTypeString, DeveloperOnlyAttribute: aws.Bool(false),
		Mutable: aws.Bool(true), Name: aws.String("identities"), Required: aws.Bool(false),
		StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{},
	},
	cognitoStrAttr("locale", true, false, "0", "2048"),
	cognitoStrAttr("middle_name", true, false, "0", "2048"),
	cognitoStrAttr("name", true, false, "0", "2048"),
	cognitoStrAttr("nickname", true, false, "0", "2048"),
	cognitoStrAttr("phone_number", true, false, "0", "2048"),
	cognitoBoolAttr("phone_number_verified", true, false),
	cognitoStrAttr("picture", true, false, "0", "2048"),
	cognitoStrAttr("preferred_username", true, false, "0", "2048"),
	cognitoStrAttr("profile", true, false, "0", "2048"),
	cognitoStrAttr("sub", false, true, "1", "2048"),
	{
		AttributeDataType: ciptypes.AttributeDataTypeNumber, DeveloperOnlyAttribute: aws.Bool(false),
		Mutable: aws.Bool(true), Name: aws.String("updated_at"), Required: aws.Bool(false),
		NumberAttributeConstraints: &ciptypes.NumberAttributeConstraintsType{MinValue: aws.String("0")},
	},
	cognitoStrAttr("website", true, false, "0", "2048"),
	cognitoStrAttr("zoneinfo", true, false, "0", "2048"),
}

func hydrateMaintenanceWindow(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ssm.NewFromConfig(c.Cfg(r.Region)).GetMaintenanceWindow(ctx, &ssm.GetMaintenanceWindowInput{WindowId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":     aws.ToString(out.Name),
		"schedule": aws.ToString(out.Schedule),
		"duration": aws.ToInt32(out.Duration),
		"cutoff":   out.Cutoff,
	}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(out.ScheduleTimezone); v != "" {
		cfg["schedule_timezone"] = v
	}
	cfg["allow_unassociated_targets"] = out.AllowUnassociatedTargets
	cfg["enabled"] = out.Enabled
	return cfg, nil
}

func hydratePatchBaseline(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	if !strings.HasPrefix(id, "pb-") {
		// ARN form is "patchbaseline/pb-xxxx"; DescribeAssociation-style id needed
		if _, rest, ok := strings.Cut(id, "/"); ok {
			id = rest
		}
	}
	out, err := ssm.NewFromConfig(c.Cfg(r.Region)).GetPatchBaseline(ctx, &ssm.GetPatchBaselineInput{BaselineId: &id})
	if err != nil {
		return nil, err
	}
	if aws.ToString(out.BaselineId) == "" {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"name": aws.ToString(out.Name)}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if v := string(out.OperatingSystem); v != "" {
		cfg["operating_system"] = v
	}
	if len(out.ApprovedPatches) > 0 {
		cfg["approved_patches"] = toAny(out.ApprovedPatches)
	}
	if v := string(out.ApprovedPatchesComplianceLevel); v != "" {
		cfg["approved_patches_compliance_level"] = v
	}
	if out.ApprovedPatchesEnableNonSecurity != nil {
		cfg["approved_patches_enable_non_security"] = *out.ApprovedPatchesEnableNonSecurity
	}
	if v := string(out.RejectedPatchesAction); v != "" {
		cfg["rejected_patches_action"] = v
	}
	if pf := patchFilters(out.GlobalFilters); len(pf) > 0 {
		cfg["global_filter"] = pf
	}
	if ar := patchApprovalRules(out.ApprovalRules); len(ar) > 0 {
		cfg["approval_rule"] = ar
	}
	if len(out.Sources) > 0 {
		var srcs []any
		for _, s := range out.Sources {
			srcs = append(srcs, map[string]any{
				"name":          aws.ToString(s.Name),
				"configuration": aws.ToString(s.Configuration),
				"products":      toAny(s.Products),
			})
		}
		cfg["source"] = srcs
	}
	if len(out.RejectedPatches) > 0 {
		cfg["rejected_patches"] = toAny(out.RejectedPatches)
	}
	return cfg, nil
}

// patchFilters turns a PatchFilterGroup into the repeatable global_filter{}
// block shape (key/values pairs).
func patchFilters(g *ssmtypes.PatchFilterGroup) []any {
	if g == nil {
		return nil
	}
	var out []any
	for _, f := range g.PatchFilters {
		out = append(out, map[string]any{"key": string(f.Key), "values": toAny(f.Values)})
	}
	return out
}

// patchApprovalRules turns a PatchRuleGroup into the repeatable approval_rule{}
// block shape: one block per PatchRule, each with its own nested
// patch_filter{} entries. approve_after_days/approve_until_date are mutually
// exclusive on a real rule -- only whichever the API actually set is emitted.
func patchApprovalRules(g *ssmtypes.PatchRuleGroup) []any {
	if g == nil {
		return nil
	}
	var out []any
	for _, rule := range g.PatchRules {
		m := map[string]any{}
		if rule.ApproveAfterDays != nil {
			m["approve_after_days"] = *rule.ApproveAfterDays
		}
		if v := aws.ToString(rule.ApproveUntilDate); v != "" {
			m["approve_until_date"] = v
		}
		if v := string(rule.ComplianceLevel); v != "" {
			m["compliance_level"] = v
		}
		if rule.EnableNonSecurity != nil {
			m["enable_non_security"] = *rule.EnableNonSecurity
		}
		if pf := patchFilters(rule.PatchFilterGroup); len(pf) > 0 {
			m["patch_filter"] = pf
		}
		out = append(out, m)
	}
	return out
}

func hydrateAppConfigApplication(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok { // "application/abcd1234"
		id = rest
	}
	out, err := appconfig.NewFromConfig(c.Cfg(r.Region)).GetApplication(ctx, &appconfig.GetApplicationInput{ApplicationId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Name)}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateAppConfigDeploymentStrategy(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok { // "deploymentstrategy/abcd1234"
		id = rest
	}
	out, err := appconfig.NewFromConfig(c.Cfg(r.Region)).GetDeploymentStrategy(ctx, &appconfig.GetDeploymentStrategyInput{DeploymentStrategyId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":                           aws.ToString(out.Name),
		"deployment_duration_in_minutes": out.DeploymentDurationInMinutes,
		"final_bake_time_in_minutes":     out.FinalBakeTimeInMinutes,
		"growth_factor":                  float64(aws.ToFloat32(out.GrowthFactor)),
		"growth_type":                    string(out.GrowthType),
		"replicate_to":                   string(out.ReplicateTo),
	}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateSDService(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := servicediscovery.NewFromConfig(c.Cfg(r.Region)).GetService(ctx, &servicediscovery.GetServiceInput{Id: &id})
	if err != nil {
		return nil, err
	}
	s := out.Service
	cfg := map[string]any{"name": aws.ToString(s.Name)}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(s.NamespaceId); v != "" {
		cfg["namespace_id"] = v
	}
	if s.DnsConfig != nil {
		dc := map[string]any{}
		if v := aws.ToString(s.DnsConfig.NamespaceId); v != "" {
			dc["namespace_id"] = v
		}
		if v := string(s.DnsConfig.RoutingPolicy); v != "" {
			dc["routing_policy"] = v
		}
		var recs []any
		for _, d := range s.DnsConfig.DnsRecords {
			recs = append(recs, map[string]any{"type": string(d.Type), "ttl": aws.ToInt64(d.TTL)})
		}
		if len(recs) > 0 {
			dc["dns_records"] = recs
		}
		cfg["dns_config"] = dc
	}
	if s.HealthCheckConfig != nil {
		cfg["health_check_config"] = map[string]any{
			"type":              string(s.HealthCheckConfig.Type),
			"resource_path":     aws.ToString(s.HealthCheckConfig.ResourcePath),
			"failure_threshold": aws.ToInt32(s.HealthCheckConfig.FailureThreshold),
		}
	}
	return cfg, nil
}

func hydrateCognitoIdentityPool(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// r.ID for arn:aws:cognito-identity:...:identitypool/<region>:<guid> is
	// "<region>:<guid>".
	id := r.ID
	out, err := cognitoidentity.NewFromConfig(c.Cfg(r.Region)).DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{
		IdentityPoolId: &id,
	})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"identity_pool_name":               aws.ToString(out.IdentityPoolName),
		"allow_unauthenticated_identities": out.AllowUnauthenticatedIdentities,
	}
	if out.AllowClassicFlow != nil {
		cfg["allow_classic_flow"] = *out.AllowClassicFlow
	}
	if v := aws.ToString(out.DeveloperProviderName); v != "" {
		cfg["developer_provider_name"] = v
	}
	if len(out.OpenIdConnectProviderARNs) > 0 {
		cfg["openid_connect_provider_arns"] = toAny(out.OpenIdConnectProviderARNs)
	}
	if len(out.SamlProviderARNs) > 0 {
		cfg["saml_provider_arns"] = toAny(out.SamlProviderARNs)
	}
	if len(out.CognitoIdentityProviders) > 0 {
		var ps []any
		for _, p := range out.CognitoIdentityProviders {
			ps = append(ps, map[string]any{
				"client_id":     aws.ToString(p.ClientId),
				"provider_name": aws.ToString(p.ProviderName),
			})
		}
		cfg["cognito_identity_providers"] = ps
	}
	if len(out.SupportedLoginProviders) > 0 {
		m := map[string]any{}
		for k, v := range out.SupportedLoginProviders {
			m[k] = v
		}
		cfg["supported_login_providers"] = m
	}
	return cfg, nil
}

func hydrateResourceExplorerIndex(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := rex.NewFromConfig(c.Cfg(r.Region)).GetIndex(ctx, &rex.GetIndexInput{})
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": string(out.Type)}, nil
}

func hydrateResourceExplorerView(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	cl := rex.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.GetView(ctx, &rex.GetViewInput{ViewArn: &arn})
	if err != nil {
		return nil, err
	}
	v := out.View
	if v == nil {
		return nil, fmt.Errorf("not found")
	}
	// the view name is the second-to-last ARN segment
	name := r.ID
	parts := strings.Split(r.ID, "/")
	if len(parts) >= 2 {
		name = parts[len(parts)-2]
	}
	cfg := map[string]any{"name": name}
	if v := aws.ToString(v.Scope); v != "" {
		cfg["scope"] = v
	}
	if v.Filters != nil && aws.ToString(v.Filters.FilterString) != "" {
		cfg["filters"] = map[string]any{"filter_string": aws.ToString(v.Filters.FilterString)}
	}
	var props []any
	for _, p := range v.IncludedProperties {
		props = append(props, map[string]any{"name": aws.ToString(p.Name)})
	}
	if len(props) > 0 {
		cfg["included_property"] = props
	}
	if dv, derr := cl.GetDefaultView(ctx, &rex.GetDefaultViewInput{}); derr == nil && aws.ToString(dv.ViewArn) == arn {
		cfg["default_view"] = true
	}
	return cfg, nil
}

func hydrateCloudFormationStackSet(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	if n, _, ok := strings.Cut(r.ID, ":"); ok { // id is "<name>:<uuid>"
		name = n
	}
	if strings.HasPrefix(name, "AWSControlTower") || strings.HasPrefix(name, "StackSet-") {
		return nil, fmt.Errorf("service-managed StackSet")
	}
	cl := cloudformation.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeStackSet(ctx, &cloudformation.DescribeStackSetInput{StackSetName: &name})
	if err != nil {
		return nil, err
	}
	s := out.StackSet
	if s == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"name": aws.ToString(s.StackSetName)}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	if v := string(s.PermissionModel); v != "" {
		cfg["permission_model"] = v
	}
	if len(s.Capabilities) > 0 {
		var caps []any
		for _, x := range s.Capabilities {
			caps = append(caps, string(x))
		}
		cfg["capabilities"] = caps
	}
	if len(s.Parameters) > 0 {
		m := map[string]any{}
		for _, p := range s.Parameters {
			m[aws.ToString(p.ParameterKey)] = aws.ToString(p.ParameterValue)
		}
		cfg["parameters"] = m
	}
	if s.AutoDeployment != nil {
		cfg["auto_deployment"] = map[string]any{
			"enabled":                          aws.ToBool(s.AutoDeployment.Enabled),
			"retain_stacks_on_account_removal": aws.ToBool(s.AutoDeployment.RetainStacksOnAccountRemoval),
		}
	}
	if v := aws.ToString(s.TemplateBody); v != "" {
		cfg["template_body"] = v
	}
	if v := aws.ToString(s.AdministrationRoleARN); v != "" {
		cfg["administration_role_arn"] = v
	}
	if v := aws.ToString(s.ExecutionRoleName); v != "" {
		cfg["execution_role_name"] = v
	}
	if s.ManagedExecution != nil {
		cfg["managed_execution"] = map[string]any{"active": aws.ToBool(s.ManagedExecution.Active)}
	}
	// call_as is a request-time directive (which permission context to act
	// under), not a real stack-set attribute; DescribeStackSet doesn't return
	// it. Self-managed stack sets are always called as SELF.
	cfg["call_as"] = "SELF"
	return cfg, nil
}

func hydrateSESv2Identity(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := sesv2.NewFromConfig(c.Cfg(r.Region)).GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"email_identity": name}
	if string(out.IdentityType) != "" {
		// identity_type is computed; kept out of config
		_ = out.IdentityType
	}
	if out.ConfigurationSetName != nil {
		cfg["configuration_set_name"] = aws.ToString(out.ConfigurationSetName)
	}
	return cfg, nil
}

func hydrateSESv2ConfigSet(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := sesv2.NewFromConfig(c.Cfg(r.Region)).GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{ConfigurationSetName: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"configuration_set_name": aws.ToString(out.ConfigurationSetName)}
	if out.ReputationOptions != nil {
		cfg["reputation_metrics_enabled"] = out.ReputationOptions.ReputationMetricsEnabled
	}
	if out.SendingOptions != nil {
		cfg["sending_enabled"] = out.SendingOptions.SendingEnabled
	}
	if out.DeliveryOptions != nil {
		d := map[string]any{}
		if v := string(out.DeliveryOptions.TlsPolicy); v != "" {
			d["tls_policy"] = v
		}
		if v := aws.ToString(out.DeliveryOptions.SendingPoolName); v != "" {
			d["sending_pool_name"] = v
		}
		if len(d) > 0 {
			cfg["delivery_options"] = d
		}
	}
	return cfg, nil
}

func hydrateSSMDocument(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	cl := ssm.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.GetDocument(ctx, &ssm.GetDocumentInput{Name: &name})
	if err != nil {
		return nil, err
	}
	if aws.ToString(out.Content) == "" {
		return nil, fmt.Errorf("empty document")
	}
	cfg := map[string]any{
		"name":            aws.ToString(out.Name),
		"document_type":   string(out.DocumentType),
		"document_format": string(out.DocumentFormat),
		"content":         aws.ToString(out.Content),
	}
	// target_type comes from DescribeDocument; the provider stores it verbatim,
	// so an unset config plans a spurious removal.
	if d, derr := cl.DescribeDocument(ctx, &ssm.DescribeDocumentInput{Name: &name}); derr == nil && d.Document != nil {
		if v := aws.ToString(d.Document.TargetType); v != "" {
			cfg["target_type"] = v
		}
	}
	return cfg, nil
}
