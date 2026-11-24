package hydrate

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"
	"github.com/aws/aws-sdk-go-v2/service/lexmodelsv2"
	lextypes "github.com/aws/aws-sdk-go-v2/service/lexmodelsv2/types"

	"github.com/virtualbeck/inherit/model"
)

func TestConnectAndLexResolve(t *testing.T) {
	for arn, want := range map[[2]string]string{
		{"connect", "instance"}: "aws_connect_instance",
		{"lex", "bot"}:          "aws_lexv2models_bot",
	} {
		if got := ResolveTFType(model.Resource{Service: arn[0], Type: arn[1]}); got != want {
			t.Errorf("%v resolves to %q, want %q", arn, got, want)
		}
		if _, ok := registry[want]; !ok {
			t.Errorf("%s has no hydrator", want)
		}
	}
}

func TestConnectInstanceConfig(t *testing.T) {
	in := connecttypes.Instance{
		IdentityManagementType: connecttypes.DirectoryTypeConnectManaged,
		InboundCallsEnabled:    aws.Bool(true), OutboundCallsEnabled: aws.Bool(false),
		InstanceAlias: aws.String("support-center"),
	}
	attrs := []connecttypes.Attribute{
		{AttributeType: connecttypes.InstanceAttributeTypeContactflowLogs, Value: aws.String("true")},
		{AttributeType: connecttypes.InstanceAttributeTypeContactLens, Value: aws.String("false")},
		{AttributeType: connecttypes.InstanceAttributeTypeEarlyMedia, Value: aws.String("true")},
		{AttributeType: connecttypes.InstanceAttributeTypeMultiPartyConference, Value: aws.String("false")},
		{AttributeType: connecttypes.InstanceAttributeTypeAutoResolveBestVoices, Value: aws.String("true")},
		{AttributeType: connecttypes.InstanceAttributeTypeHighVolumeOutbound, Value: aws.String("true")},
	}
	got := connectInstanceConfig(&connect.DescribeInstanceOutput{Instance: &in}, attrs)
	want := map[string]any{
		"identity_management_type": "CONNECT_MANAGED", "inbound_calls_enabled": true, "outbound_calls_enabled": false,
		"instance_alias": "support-center", "contact_flow_logs_enabled": true, "contact_lens_enabled": false,
		"early_media_enabled": true, "multi_party_conference_enabled": false, "auto_resolve_best_voices_enabled": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("connectInstanceConfig =\n%#v\nwant\n%#v", got, want)
	}
}

func TestLexBotConfig(t *testing.T) {
	got := lexBotConfig(&lexmodelsv2.DescribeBotOutput{
		BotName: aws.String("support"), RoleArn: aws.String("arn:aws:iam::1:role/lex"), IdleSessionTTLInSeconds: aws.Int32(300),
		Description: aws.String("triage bot"), BotType: lextypes.BotTypeBot,
		DataPrivacy: &lextypes.DataPrivacy{ChildDirected: false},
	})
	want := map[string]any{
		"name": "support", "role_arn": "arn:aws:iam::1:role/lex", "idle_session_ttl_in_seconds": int32(300),
		"description": "triage bot", "type": "Bot", "data_privacy": []any{map[string]any{"child_directed": false}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lexBotConfig =\n%#v\nwant\n%#v", got, want)
	}
	network := lexBotConfig(&lexmodelsv2.DescribeBotOutput{
		BotName: aws.String("hub"), RoleArn: aws.String("r"), IdleSessionTTLInSeconds: aws.Int32(60), BotType: lextypes.BotTypeBotNetwork,
		BotMembers: []lextypes.BotMember{{BotMemberId: aws.String("B1"), BotMemberName: aws.String("support"),
			BotMemberAliasId: aws.String("A1"), BotMemberAliasName: aws.String("live"), BotMemberVersion: aws.String("3")}},
	})
	if m, _ := network["members"].([]any); len(m) != 1 || !reflect.DeepEqual(m[0], map[string]any{"id": "B1", "name": "support", "alias_id": "A1", "alias_name": "live", "version": "3"}) {
		t.Errorf("members = %#v", network["members"])
	}
}
