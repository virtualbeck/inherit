package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ebr "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/virtualbeck/inherit-core/internal/nameconv"
	"github.com/virtualbeck/inherit-core/model"
	"github.com/virtualbeck/inherit-core/tfschema"
)

func init() {
	register("aws_sns_topic", hydrateSNSTopic)
	register("aws_sqs_queue", hydrateSQSQueue)
	register("aws_cloudwatch_event_bus", hydrateEventBus)
	register("aws_cloudwatch_event_rule", hydrateEventRule)
	register("aws_kinesis_stream", hydrateKinesisStream)
	register("aws_kinesis_firehose_delivery_stream", hydrateFirehose)
	register("aws_msk_cluster", hydrateMSK)
	register("aws_mq_broker", hydrateMQ)
	register("aws_scheduler_schedule_group", hydrateSchedulerGroup)
	register("aws_scheduler_schedule", hydrateSchedulerSchedule)
}

func hydrateSNSTopic(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_sns_topic")
	if err != nil {
		return nil, err
	}
	out, err := sns.NewFromConfig(c.Cfg(r.Region)).GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	cfg := attrsToConfig(out.Attributes, sch)
	cfg["name"] = r.ID
	return cfg, nil
}

func hydrateSQSQueue(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_sqs_queue")
	if err != nil {
		return nil, err
	}
	cl := sqs.NewFromConfig(c.Cfg(r.Region))
	u, err := cl.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &r.ID})
	if err != nil {
		return nil, err
	}
	out, err := cl.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       u.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll},
	})
	if err != nil {
		return nil, err
	}
	cfg := attrsToConfig(out.Attributes, sch)
	cfg["name"] = r.ID
	return cfg, nil
}

// attrsToConfig turns an AWS "Attributes" string map (SNS/SQS style) into a
// schema-filtered TF config map. "policy" is always skipped even though both
// aws_sqs_queue and aws_sns_topic still carry an Optional+Computed `policy`
// attribute for backward compatibility: this account's queue/topic policy is
// already emitted as its own aws_sqs_queue_policy/aws_sns_topic_policy
// resource (fanoutSQSPolicy / fanoutSNSPolicy), and declaring the same real
// policy both inline and standalone is two resources fighting over the same
// attachment on any future apply.
func attrsToConfig(attrs map[string]string, sch *tfschema.Block) map[string]any {
	cfg := map[string]any{}
	for k, v := range attrs {
		if v == "" || k == "Policy" {
			continue
		}
		snake := nameconv.Snake(k)
		a, ok := sch.Attr(snake)
		if !ok || !a.Settable() {
			continue
		}
		cfg[snake] = coerceScalar(a, v)
	}
	return cfg
}

func coerceScalar(a *tfschema.Attribute, v string) any {
	if a.Type == nil {
		return v
	}
	switch a.Type.Kind {
	case tfschema.KindBool:
		return v == "true"
	case tfschema.KindNumber:
		var n float64
		if _, err := fmt.Sscanf(v, "%g", &n); err == nil {
			return n
		}
	}
	return v
}

func hydrateEventBus(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := ebr.NewFromConfig(c.Cfg(r.Region)).DescribeEventBus(ctx, &ebr.DescribeEventBusInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Name)}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(out.KmsKeyIdentifier); v != "" {
		cfg["kms_key_identifier"] = v
	}
	if dlq := out.DeadLetterConfig; dlq != nil && aws.ToString(dlq.Arn) != "" {
		cfg["dead_letter_config"] = map[string]any{"arn": aws.ToString(dlq.Arn)}
	}
	if lc := out.LogConfig; lc != nil {
		cfg["log_config"] = map[string]any{
			"include_detail": string(lc.IncludeDetail),
			"level":          string(lc.Level),
		}
	}
	return cfg, nil
}

func hydrateKinesisStream(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := kinesis.NewFromConfig(c.Cfg(r.Region)).DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamName: &r.ID})
	if err != nil {
		return nil, err
	}
	d := out.StreamDescriptionSummary
	cfg := map[string]any{
		"name":             aws.ToString(d.StreamName),
		"retention_period": aws.ToInt32(d.RetentionPeriodHours),
	}
	onDemand := d.StreamModeDetails != nil && string(d.StreamModeDetails.StreamMode) == "ON_DEMAND"
	if d.StreamModeDetails != nil {
		cfg["stream_mode_details"] = map[string]any{"stream_mode": string(d.StreamModeDetails.StreamMode)}
	}
	if n := aws.ToInt32(d.OpenShardCount); n > 0 && !onDemand {
		cfg["shard_count"] = n
	}
	return cfg, nil
}

func hydrateFirehose(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := firehose.NewFromConfig(c.Cfg(r.Region)).DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{
		DeliveryStreamName: &name,
	})
	if err != nil {
		return nil, err
	}
	d := out.DeliveryStreamDescription
	if d == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"name": aws.ToString(d.DeliveryStreamName)}
	if len(d.Destinations) == 0 {
		return cfg, nil
	}
	dest := d.Destinations[0]
	switch {
	case dest.ExtendedS3DestinationDescription != nil:
		s := dest.ExtendedS3DestinationDescription
		cfg["destination"] = "extended_s3"
		e := map[string]any{
			"role_arn":   aws.ToString(s.RoleARN),
			"bucket_arn": aws.ToString(s.BucketARN),
		}
		if v := aws.ToString(s.Prefix); v != "" {
			e["prefix"] = v
		}
		if v := aws.ToString(s.ErrorOutputPrefix); v != "" {
			e["error_output_prefix"] = v
		}
		if v := string(s.CompressionFormat); v != "" {
			e["compression_format"] = v
		}
		if s.BufferingHints != nil {
			if s.BufferingHints.SizeInMBs != nil {
				e["buffering_size"] = *s.BufferingHints.SizeInMBs
			}
			if s.BufferingHints.IntervalInSeconds != nil {
				e["buffering_interval"] = *s.BufferingHints.IntervalInSeconds
			}
		}
		cfg["extended_s3_configuration"] = e
	// The other 4 destination types each carry their own Required
	// s3_configuration block (min_items:1 in the schema) -- Firehose always
	// needs an S3 backup target even when the primary destination is
	// something else. tofu validate doesn't catch a missing one because the
	// outer *_configuration block itself is Optional, but a real plan after
	// import would show the whole block appearing from nothing.
	case dest.HttpEndpointDestinationDescription != nil:
		s := dest.HttpEndpointDestinationDescription
		cfg["destination"] = "http_endpoint"
		h := map[string]any{}
		if s.EndpointConfiguration != nil {
			h["url"] = aws.ToString(s.EndpointConfiguration.Url)
			if v := aws.ToString(s.EndpointConfiguration.Name); v != "" {
				h["name"] = v
			}
		}
		if v := aws.ToString(s.RoleARN); v != "" {
			h["role_arn"] = v
		}
		if sc := firehoseS3Config(s.S3DestinationDescription); sc != nil {
			h["s3_configuration"] = sc
		}
		cfg["http_endpoint_configuration"] = h
	case dest.RedshiftDestinationDescription != nil:
		s := dest.RedshiftDestinationDescription
		cfg["destination"] = "redshift"
		rc := map[string]any{
			"cluster_jdbcurl": aws.ToString(s.ClusterJDBCURL),
			"role_arn":        aws.ToString(s.RoleARN),
		}
		if s.CopyCommand != nil {
			rc["data_table_name"] = aws.ToString(s.CopyCommand.DataTableName)
			if v := aws.ToString(s.CopyCommand.DataTableColumns); v != "" {
				rc["data_table_columns"] = v
			}
			if v := aws.ToString(s.CopyCommand.CopyOptions); v != "" {
				rc["copy_options"] = v
			}
		}
		if v := aws.ToString(s.Username); v != "" {
			rc["username"] = v
		}
		if sc := firehoseS3Config(s.S3DestinationDescription); sc != nil {
			rc["s3_configuration"] = sc
		}
		cfg["redshift_configuration"] = rc
	case dest.ElasticsearchDestinationDescription != nil:
		s := dest.ElasticsearchDestinationDescription
		cfg["destination"] = "elasticsearch"
		ec := map[string]any{
			"index_name": aws.ToString(s.IndexName),
			"role_arn":   aws.ToString(s.RoleARN),
		}
		if v := aws.ToString(s.DomainARN); v != "" {
			ec["domain_arn"] = v
		}
		if v := aws.ToString(s.ClusterEndpoint); v != "" {
			ec["cluster_endpoint"] = v
		}
		if v := string(s.IndexRotationPeriod); v != "" {
			ec["index_rotation_period"] = v
		}
		if v := aws.ToString(s.TypeName); v != "" {
			ec["type_name"] = v
		}
		if sc := firehoseS3Config(s.S3DestinationDescription); sc != nil {
			ec["s3_configuration"] = sc
		}
		cfg["elasticsearch_configuration"] = ec
	case dest.SplunkDestinationDescription != nil:
		s := dest.SplunkDestinationDescription
		cfg["destination"] = "splunk"
		sp := map[string]any{"hec_endpoint": aws.ToString(s.HECEndpoint)}
		if v := string(s.HECEndpointType); v != "" {
			sp["hec_endpoint_type"] = v
		}
		if s.HECAcknowledgmentTimeoutInSeconds != nil {
			sp["hec_acknowledgment_timeout"] = *s.HECAcknowledgmentTimeoutInSeconds
		}
		if sc := firehoseS3Config(s.S3DestinationDescription); sc != nil {
			sp["s3_configuration"] = sc
		}
		cfg["splunk_configuration"] = sp
	}
	return cfg, nil
}

// firehoseS3Config builds the s3_configuration block shared by the
// redshift/elasticsearch/http_endpoint/splunk destination configs (a
// different, older S3DestinationDescription shape than extended_s3's own
// ExtendedS3DestinationDescription).
func firehoseS3Config(s *fhtypes.S3DestinationDescription) map[string]any {
	if s == nil {
		return nil
	}
	m := map[string]any{
		"bucket_arn": aws.ToString(s.BucketARN),
		"role_arn":   aws.ToString(s.RoleARN),
	}
	if v := aws.ToString(s.Prefix); v != "" {
		m["prefix"] = v
	}
	if v := aws.ToString(s.ErrorOutputPrefix); v != "" {
		m["error_output_prefix"] = v
	}
	if v := string(s.CompressionFormat); v != "" {
		m["compression_format"] = v
	}
	if s.BufferingHints != nil {
		if s.BufferingHints.SizeInMBs != nil {
			m["buffering_size"] = *s.BufferingHints.SizeInMBs
		}
		if s.BufferingHints.IntervalInSeconds != nil {
			m["buffering_interval"] = *s.BufferingHints.IntervalInSeconds
		}
	}
	return m
}

func hydrateMSK(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := kafka.NewFromConfig(c.Cfg(r.Region)).DescribeCluster(ctx, &kafka.DescribeClusterInput{ClusterArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	ci := out.ClusterInfo
	cfg := map[string]any{
		"cluster_name":           aws.ToString(ci.ClusterName),
		"number_of_broker_nodes": aws.ToInt32(ci.NumberOfBrokerNodes),
	}
	if ci.CurrentBrokerSoftwareInfo != nil {
		cfg["kafka_version"] = aws.ToString(ci.CurrentBrokerSoftwareInfo.KafkaVersion)
	}
	if bng := ci.BrokerNodeGroupInfo; bng != nil {
		bn := map[string]any{"instance_type": aws.ToString(bng.InstanceType)}
		if len(bng.ClientSubnets) > 0 {
			bn["client_subnets"] = toAny(bng.ClientSubnets)
		}
		if len(bng.SecurityGroups) > 0 {
			bn["security_groups"] = toAny(bng.SecurityGroups)
		}
		if bng.StorageInfo != nil && bng.StorageInfo.EbsStorageInfo != nil && bng.StorageInfo.EbsStorageInfo.VolumeSize != nil {
			bn["storage_info"] = map[string]any{
				"ebs_storage_info": map[string]any{"volume_size": *bng.StorageInfo.EbsStorageInfo.VolumeSize},
			}
		}
		cfg["broker_node_group_info"] = bn
	}
	// encryption_info/client_authentication: the schema's shape doesn't
	// mirror the SDK's structs closely enough for Generic() --
	// encryption_at_rest_kms_key_arn is a flat scalar in Terraform but
	// nested under EncryptionAtRest in the SDK, and sasl.iam/sasl.scram are
	// plain bools in Terraform but {Enabled *bool} structs in the SDK.
	if ei := ci.EncryptionInfo; ei != nil {
		einfo := map[string]any{}
		if ei.EncryptionAtRest != nil {
			einfo["encryption_at_rest_kms_key_arn"] = aws.ToString(ei.EncryptionAtRest.DataVolumeKMSKeyId)
		}
		if eit := ei.EncryptionInTransit; eit != nil {
			eitm := map[string]any{}
			if v := string(eit.ClientBroker); v != "" {
				eitm["client_broker"] = v
			}
			if eit.InCluster != nil {
				eitm["in_cluster"] = *eit.InCluster
			}
			if len(eitm) > 0 {
				einfo["encryption_in_transit"] = eitm
			}
		}
		if len(einfo) > 0 {
			cfg["encryption_info"] = einfo
		}
	}
	if ca := ci.ClientAuthentication; ca != nil {
		cam := map[string]any{}
		if ca.Unauthenticated != nil && ca.Unauthenticated.Enabled != nil {
			cam["unauthenticated"] = *ca.Unauthenticated.Enabled
		}
		if s := ca.Sasl; s != nil {
			sm := map[string]any{}
			if s.Iam != nil && s.Iam.Enabled != nil {
				sm["iam"] = *s.Iam.Enabled
			}
			if s.Scram != nil && s.Scram.Enabled != nil {
				sm["scram"] = *s.Scram.Enabled
			}
			if len(sm) > 0 {
				cam["sasl"] = []any{sm}
			}
		}
		if t := ca.Tls; t != nil && len(t.CertificateAuthorityArnList) > 0 {
			cam["tls"] = []any{map[string]any{"certificate_authority_arns": toAny(t.CertificateAuthorityArnList)}}
		}
		if len(cam) > 0 {
			cfg["client_authentication"] = cam
		}
	}
	return cfg, nil
}

func hydrateMQ(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := mq.NewFromConfig(c.Cfg(r.Region)).DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &r.ID})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"broker_name":        aws.ToString(out.BrokerName),
		"engine_type":        string(out.EngineType),
		"engine_version":     aws.ToString(out.EngineVersion),
		"host_instance_type": aws.ToString(out.HostInstanceType),
		"deployment_mode":    string(out.DeploymentMode),
	}
	if out.PubliclyAccessible != nil {
		cfg["publicly_accessible"] = *out.PubliclyAccessible
	}
	if len(out.SubnetIds) > 0 {
		cfg["subnet_ids"] = toAny(out.SubnetIds)
	}
	if len(out.SecurityGroups) > 0 {
		cfg["security_groups"] = toAny(out.SecurityGroups)
	}
	// encryption_options/logs/configuration: a broker with a custom
	// configuration applied has nothing else recoverable describing it
	// without these.
	if eo := out.EncryptionOptions; eo != nil {
		m := map[string]any{}
		if eo.UseAwsOwnedKey != nil {
			m["use_aws_owned_key"] = *eo.UseAwsOwnedKey
		}
		if v := aws.ToString(eo.KmsKeyId); v != "" {
			m["kms_key_id"] = v
		}
		if len(m) > 0 {
			cfg["encryption_options"] = m
		}
	}
	if lg := out.Logs; lg != nil {
		m := map[string]any{}
		if lg.General != nil {
			m["general"] = *lg.General
		}
		if lg.Audit != nil {
			m["audit"] = *lg.Audit
		}
		if len(m) > 0 {
			cfg["logs"] = m
		}
	}
	if cfgs := out.Configurations; cfgs != nil && cfgs.Current != nil {
		cfg["configuration"] = map[string]any{
			"id":       aws.ToString(cfgs.Current.Id),
			"revision": aws.ToInt32(cfgs.Current.Revision),
		}
	}
	return cfg, nil
}

func hydrateSchedulerGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := scheduler.NewFromConfig(c.Cfg(r.Region)).GetScheduleGroup(ctx, &scheduler.GetScheduleGroupInput{Name: &name})
	if err != nil {
		return nil, err
	}
	return map[string]any{"name": aws.ToString(out.Name)}, nil
}

func hydrateSchedulerSchedule(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	group, name := "default", r.ID
	if g, n, ok := strings.Cut(r.ID, "/"); ok {
		group, name = g, n
	}
	out, err := scheduler.NewFromConfig(c.Cfg(r.Region)).GetSchedule(ctx, &scheduler.GetScheduleInput{
		GroupName: &group, Name: &name,
	})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":                aws.ToString(out.Name),
		"schedule_expression": aws.ToString(out.ScheduleExpression),
	}
	if v := aws.ToString(out.GroupName); v != "" && v != "default" {
		cfg["group_name"] = v
	}
	if v := aws.ToString(out.ScheduleExpressionTimezone); v != "" && v != "UTC" {
		cfg["schedule_expression_timezone"] = v
	}
	if v := string(out.State); v != "" {
		cfg["state"] = v
	}
	if v := string(out.ActionAfterCompletion); v != "" {
		cfg["action_after_completion"] = v
	}
	if out.FlexibleTimeWindow != nil {
		ftw := map[string]any{"mode": string(out.FlexibleTimeWindow.Mode)}
		if out.FlexibleTimeWindow.MaximumWindowInMinutes != nil {
			ftw["maximum_window_in_minutes"] = *out.FlexibleTimeWindow.MaximumWindowInMinutes
		}
		cfg["flexible_time_window"] = ftw
	}
	if t := out.Target; t != nil {
		target := map[string]any{"arn": aws.ToString(t.Arn), "role_arn": aws.ToString(t.RoleArn)}
		if v := aws.ToString(t.Input); v != "" {
			target["input"] = v
		}
		cfg["target"] = target
	}
	return cfg, nil
}

func hydrateEventRule(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_cloudwatch_event_rule")
	if err != nil {
		return nil, err
	}
	// r.ID is "rule-name" on the default bus, but SplitResource only splits
	// on the FIRST '/' of the ARN's resource segment ("rule/bus-name/rule-name"),
	// so a custom-bus rule's ID actually arrives as "bus-name/rule-name" --
	// passing that whole string as DescribeRule's bare Name (with no
	// EventBusName) looks up the wrong rule on the default bus entirely and
	// 404s.
	ruleName, busName := r.ID, ""
	if i := strings.LastIndexByte(r.ID, '/'); i >= 0 {
		busName, ruleName = r.ID[:i], r.ID[i+1:]
	}
	in := &ebr.DescribeRuleInput{Name: &ruleName}
	if busName != "" {
		in.EventBusName = &busName
	}
	out, err := ebr.NewFromConfig(c.Cfg(r.Region)).DescribeRule(ctx, in)
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out, sch, nil)
	if err != nil {
		return nil, err
	}
	// State ("ENABLED"/"DISABLED") -> the v6 `state` attribute takes those verbatim
	if s := string(out.State); s != "" {
		cfg["state"] = s
	}
	if busName != "" {
		cfg["event_bus_name"] = busName
	}
	return cfg, nil
}
