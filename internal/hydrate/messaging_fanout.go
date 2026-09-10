package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ebr "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebrtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_cloudwatch_event_rule", fanoutEventTargets)
	registerFanout("aws_sns_topic", fanoutSNSSubscriptions)
	registerFanout("aws_sqs_queue", fanoutSQSPolicy)
}

func fanoutEventTargets(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	// parent.ID is "rule-name" on the default bus, but SplitResource only
	// splits on the FIRST '/' of the ARN's resource segment
	// ("rule/bus-name/rule-name"), so a custom-bus rule's ID actually
	// arrives as "bus-name/rule-name" -- passing that whole string as
	// ListTargetsByRule's bare Rule name (with no EventBusName) looks up the
	// wrong rule on the default bus entirely and returns nothing.
	ruleName, busName := parent.ID, ""
	if i := strings.LastIndexByte(parent.ID, '/'); i >= 0 {
		busName, ruleName = parent.ID[:i], parent.ID[i+1:]
	}
	in := &ebr.ListTargetsByRuleInput{Rule: &ruleName}
	if busName != "" {
		in.EventBusName = &busName
	}
	out, err := ebr.NewFromConfig(c.Cfg(parent.Region)).ListTargetsByRule(ctx, in)
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, t := range out.Targets {
		cfg := map[string]any{
			"rule":      ruleName,
			"target_id": aws.ToString(t.Id),
			"arn":       aws.ToString(t.Arn),
		}
		if busName != "" {
			cfg["event_bus_name"] = busName
		}
		if v := aws.ToString(t.RoleArn); v != "" {
			cfg["role_arn"] = v
		}
		if v := aws.ToString(t.Input); v != "" {
			cfg["input"] = v
		}
		if v := aws.ToString(t.InputPath); v != "" {
			cfg["input_path"] = v
		}
		if it := t.InputTransformer; it != nil {
			tr := map[string]any{"input_template": aws.ToString(it.InputTemplate)}
			if len(it.InputPathsMap) > 0 {
				m := map[string]any{}
				for k, v := range it.InputPathsMap {
					m[k] = v
				}
				tr["input_paths"] = m
			}
			cfg["input_transformer"] = tr
		}
		if dl := t.DeadLetterConfig; dl != nil && aws.ToString(dl.Arn) != "" {
			cfg["dead_letter_config"] = map[string]any{"arn": aws.ToString(dl.Arn)}
		}
		if rp := t.RetryPolicy; rp != nil {
			m := map[string]any{}
			if rp.MaximumEventAgeInSeconds != nil {
				m["maximum_event_age_in_seconds"] = *rp.MaximumEventAgeInSeconds
			}
			if rp.MaximumRetryAttempts != nil {
				m["maximum_retry_attempts"] = *rp.MaximumRetryAttempts
			}
			if len(m) > 0 {
				cfg["retry_policy"] = m
			}
		}
		if sq := t.SqsParameters; sq != nil {
			if v := aws.ToString(sq.MessageGroupId); v != "" {
				cfg["sqs_target"] = map[string]any{"message_group_id": v}
			}
		}
		if ep := t.EcsParameters; ep != nil {
			cfg["ecs_target"] = ecsTargetConfig(ep)
		}
		kids = append(kids, model.Resource{
			Service: "events", Type: "target", TFType: "aws_cloudwatch_event_target",
			Region: parent.Region, Account: parent.Account,
			ID:     parent.ID + "/" + aws.ToString(t.Id),
			Config: cfg,
		})
	}
	return kids, nil
}

// ecsTargetConfig renders EcsParameters as ecs_target{}. Tags/ReferenceId
// have no schema counterpart on this resource and are dropped.
func ecsTargetConfig(ep *ebrtypes.EcsParameters) map[string]any {
	m := map[string]any{"task_definition_arn": aws.ToString(ep.TaskDefinitionArn)}
	if v := string(ep.LaunchType); v != "" {
		m["launch_type"] = v
	}
	if v := aws.ToString(ep.Group); v != "" {
		m["group"] = v
	}
	if v := aws.ToString(ep.PlatformVersion); v != "" {
		m["platform_version"] = v
	}
	if v := string(ep.PropagateTags); v != "" {
		m["propagate_tags"] = v
	}
	if ep.TaskCount != nil {
		m["task_count"] = *ep.TaskCount
	}
	if ep.EnableECSManagedTags {
		m["enable_ecs_managed_tags"] = true
	}
	if ep.EnableExecuteCommand {
		m["enable_execute_command"] = true
	}
	if len(ep.CapacityProviderStrategy) > 0 {
		var cps []any
		for _, s := range ep.CapacityProviderStrategy {
			cm := map[string]any{"capacity_provider": aws.ToString(s.CapacityProvider)}
			if s.Base != 0 {
				cm["base"] = s.Base
			}
			if s.Weight != 0 {
				cm["weight"] = s.Weight
			}
			cps = append(cps, cm)
		}
		m["capacity_provider_strategy"] = cps
	}
	if nc := ep.NetworkConfiguration; nc != nil && nc.AwsvpcConfiguration != nil {
		vc := nc.AwsvpcConfiguration
		ncm := map[string]any{"subnets": toAny(vc.Subnets)}
		if len(vc.SecurityGroups) > 0 {
			ncm["security_groups"] = toAny(vc.SecurityGroups)
		}
		if vc.AssignPublicIp == ebrtypes.AssignPublicIpEnabled {
			ncm["assign_public_ip"] = true
		}
		m["network_configuration"] = []any{ncm}
	}
	if len(ep.PlacementConstraints) > 0 {
		var pcs []any
		for _, pc := range ep.PlacementConstraints {
			pcm := map[string]any{"type": string(pc.Type)}
			if v := aws.ToString(pc.Expression); v != "" {
				pcm["expression"] = v
			}
			pcs = append(pcs, pcm)
		}
		m["placement_constraint"] = pcs
	}
	if len(ep.PlacementStrategy) > 0 {
		var pss []any
		for _, ps := range ep.PlacementStrategy {
			psm := map[string]any{"type": string(ps.Type)}
			if v := aws.ToString(ps.Field); v != "" {
				psm["field"] = v
			}
			pss = append(pss, psm)
		}
		m["ordered_placement_strategy"] = pss
	}
	return m
}

func fanoutSNSSubscriptions(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := sns.NewFromConfig(c.Cfg(parent.Region))
	out, err := cl.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{TopicArn: &parent.ARN})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_sns_topic_subscription")
	if err != nil {
		return nil, err
	}
	kids := fanoutSNSPolicy(ctx, cl, parent)
	for _, s := range out.Subscriptions {
		arn := aws.ToString(s.SubscriptionArn)
		if arn == "" || arn == "PendingConfirmation" {
			continue
		}
		cfg := map[string]any{
			"topic_arn": aws.ToString(s.TopicArn),
			"protocol":  aws.ToString(s.Protocol),
			"endpoint":  aws.ToString(s.Endpoint),
		}
		if attrs, err := cl.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{SubscriptionArn: &arn}); err == nil {
			for k, v := range attrsToConfig(attrs.Attributes, sch) {
				cfg[k] = v
			}
		}
		// confirmation_timeout_in_minutes / endpoint_auto_confirms are pure
		// provider directives for the (already-past) subscribe call; AWS has
		// no such attributes to read back. Pin them to the provider defaults
		// so the plan doesn't offer to "add" them.
		if _, ok := cfg["confirmation_timeout_in_minutes"]; !ok {
			cfg["confirmation_timeout_in_minutes"] = float64(1)
		}
		if _, ok := cfg["endpoint_auto_confirms"]; !ok {
			cfg["endpoint_auto_confirms"] = false
		}
		kids = append(kids, model.Resource{
			Service: "sns", Type: "subscription", TFType: "aws_sns_topic_subscription",
			Region: parent.Region, Account: parent.Account, ARN: arn, ID: arn,
			Config: cfg,
		})
	}
	return kids, nil
}

func fanoutSQSPolicy(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := sqs.NewFromConfig(c.Cfg(parent.Region))
	u, err := cl.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &parent.ID})
	if err != nil {
		return nil, err
	}
	url := aws.ToString(u.QueueUrl)
	out, err := cl.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       u.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy},
	})
	if err != nil {
		return nil, err
	}
	pol := out.Attributes[string(sqstypes.QueueAttributeNamePolicy)]
	if pol == "" {
		return nil, nil
	}
	return []model.Resource{{
		Service: "sqs", Type: "queue-policy", TFType: "aws_sqs_queue_policy",
		Region: parent.Region, Account: parent.Account,
		ID:     url,
		Config: map[string]any{"queue_url": url, "policy": pol},
	}}, nil
}

// fanoutSNSPolicy turns a topic's access policy into an aws_sns_topic_policy.
// Called from fanoutSNSSubscriptions.
func fanoutSNSPolicy(ctx context.Context, cl *sns.Client, parent model.Resource) []model.Resource {
	arn := parent.ARN
	out, err := cl.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: &arn})
	if err != nil {
		return nil
	}
	pol := out.Attributes["Policy"]
	if pol == "" {
		return nil
	}
	return []model.Resource{{
		Service: "sns", Type: "topic-policy", TFType: "aws_sns_topic_policy",
		Region: parent.Region, Account: parent.Account,
		ID:     arn,
		Config: map[string]any{"arn": arn, "policy": pol},
	}}
}

func firstString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		if len(x) > 0 {
			if s, ok := x[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
