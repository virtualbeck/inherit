package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"
	"github.com/aws/aws-sdk-go-v2/service/lexmodelsv2"

	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_connect_instance", hydrateConnectInstance)
	register("aws_lexv2models_bot", hydrateLexBot)
}

var connectInstanceAttributes = map[connecttypes.InstanceAttributeType]string{
	connecttypes.InstanceAttributeTypeContactflowLogs:       "contact_flow_logs_enabled",
	connecttypes.InstanceAttributeTypeContactLens:           "contact_lens_enabled",
	connecttypes.InstanceAttributeTypeEarlyMedia:            "early_media_enabled",
	connecttypes.InstanceAttributeTypeMultiPartyConference:  "multi_party_conference_enabled",
	connecttypes.InstanceAttributeTypeAutoResolveBestVoices: "auto_resolve_best_voices_enabled",
}

func hydrateConnectInstance(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := connect.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeInstance(ctx, &connect.DescribeInstanceInput{InstanceId: &r.ID})
	if err != nil {
		return nil, err
	}
	if out.Instance == nil {
		return nil, fmt.Errorf("not found")
	}
	var attrs []connecttypes.Attribute
	p := connect.NewListInstanceAttributesPaginator(cl, &connect.ListInstanceAttributesInput{InstanceId: &r.ID})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, page.Attributes...)
	}
	return connectInstanceConfig(out, attrs), nil
}

func connectInstanceConfig(out *connect.DescribeInstanceOutput, attrs []connecttypes.Attribute) map[string]any {
	in := out.Instance
	cfg := map[string]any{
		"identity_management_type": string(in.IdentityManagementType),
		"inbound_calls_enabled":    aws.ToBool(in.InboundCallsEnabled),
		"outbound_calls_enabled":   aws.ToBool(in.OutboundCallsEnabled),
	}
	if a := aws.ToString(in.InstanceAlias); a != "" {
		cfg["instance_alias"] = a
	}
	for _, a := range attrs {
		if key, ok := connectInstanceAttributes[a.AttributeType]; ok {
			cfg[key] = aws.ToString(a.Value) == "true"
		}
	}
	return cfg
}

// r.ID is the bot ID (Lex V2).
func hydrateLexBot(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := lexmodelsv2.NewFromConfig(c.Cfg(r.Region)).DescribeBot(ctx, &lexmodelsv2.DescribeBotInput{BotId: &r.ID})
	if err != nil {
		return nil, err
	}
	return lexBotConfig(out), nil
}

func lexBotConfig(out *lexmodelsv2.DescribeBotOutput) map[string]any {
	cfg := map[string]any{
		"name":                        aws.ToString(out.BotName),
		"role_arn":                    aws.ToString(out.RoleArn),
		"idle_session_ttl_in_seconds": aws.ToInt32(out.IdleSessionTTLInSeconds),
	}
	if d := aws.ToString(out.Description); d != "" {
		cfg["description"] = d
	}
	if t := string(out.BotType); t != "" {
		cfg["type"] = t
	}
	if dp := out.DataPrivacy; dp != nil {
		cfg["data_privacy"] = []any{map[string]any{"child_directed": dp.ChildDirected}}
	}
	var members []any
	for _, m := range out.BotMembers {
		members = append(members, map[string]any{
			"id": aws.ToString(m.BotMemberId), "name": aws.ToString(m.BotMemberName),
			"alias_id": aws.ToString(m.BotMemberAliasId), "alias_name": aws.ToString(m.BotMemberAliasName),
			"version": aws.ToString(m.BotMemberVersion),
		})
	}
	if len(members) > 0 {
		cfg["members"] = members
	}
	return cfg
}
