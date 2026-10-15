package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_lb_listener", fanoutListenerRules)
}

// Non-default rules become aws_lb_listener_rule.
func fanoutListenerRules(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	out, err := elb.NewFromConfig(c.Cfg(parent.Region)).DescribeRules(ctx, &elb.DescribeRulesInput{ListenerArn: &parent.ARN})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, rule := range out.Rules {
		if aws.ToString(rule.Priority) == "default" || aws.ToBool(rule.IsDefault) {
			continue
		}
		cfg := map[string]any{
			"listener_arn": parent.ARN,
			"priority":     aws.ToString(rule.Priority),
		}
		if conds := lbConditions(rule.Conditions); len(conds) > 0 {
			cfg["condition"] = conds
		}
		if acts := lbActions(rule.Actions); len(acts) > 0 {
			cfg["action"] = acts
		}
		if tags := lbRuleTags(ctx, c, parent.Region, aws.ToString(rule.RuleArn)); len(tags) > 0 {
			cfg["tags"] = tags
		}
		kids = append(kids, model.Resource{
			Service: "elasticloadbalancing", Type: "listener-rule", TFType: "aws_lb_listener_rule",
			Region: parent.Region, Account: parent.Account,
			ARN: aws.ToString(rule.RuleArn), ID: aws.ToString(rule.RuleArn),
			Config: cfg,
		})
	}
	if certs := lbListenerCertificates(ctx, c, parent); len(certs) > 0 {
		kids = append(kids, certs...)
	}
	return kids, nil
}

// Extra SNI certs; the listener holds the default.
func lbListenerCertificates(ctx context.Context, c *Clients, parent model.Resource) []model.Resource {
	out, err := elb.NewFromConfig(c.Cfg(parent.Region)).DescribeListenerCertificates(ctx, &elb.DescribeListenerCertificatesInput{
		ListenerArn: &parent.ARN,
	})
	if err != nil {
		return nil
	}
	var kids []model.Resource
	for _, cert := range out.Certificates {
		if aws.ToBool(cert.IsDefault) {
			continue
		}
		arn := aws.ToString(cert.CertificateArn)
		if arn == "" {
			continue
		}
		id := parent.ARN + "_" + arn
		kids = append(kids, model.Resource{
			Service: "elasticloadbalancing", Type: "listener-certificate", TFType: "aws_lb_listener_certificate",
			Region: parent.Region, Account: parent.Account,
			ID: id,
			Config: map[string]any{
				"listener_arn":    parent.ARN,
				"certificate_arn": arn,
			},
		})
	}
	return kids
}

// DescribeRules omits tags.
func lbRuleTags(ctx context.Context, c *Clients, region, ruleARN string) map[string]string {
	out, err := elb.NewFromConfig(c.Cfg(region)).DescribeTags(ctx, &elb.DescribeTagsInput{ResourceArns: []string{ruleARN}})
	if err != nil || len(out.TagDescriptions) == 0 {
		return nil
	}
	tags := map[string]string{}
	for _, t := range out.TagDescriptions[0].Tags {
		if k := aws.ToString(t.Key); k != "" {
			tags[k] = aws.ToString(t.Value)
		}
	}
	return tags
}

func lbConditions(cs []elbtypes.RuleCondition) []any {
	var out []any
	for _, c := range cs {
		cond := map[string]any{}
		switch {
		case c.HostHeaderConfig != nil:
			cond["host_header"] = map[string]any{"values": toAny(c.HostHeaderConfig.Values)}
		case c.PathPatternConfig != nil:
			cond["path_pattern"] = map[string]any{"values": toAny(c.PathPatternConfig.Values)}
		case c.HttpRequestMethodConfig != nil:
			cond["http_request_method"] = map[string]any{"values": toAny(c.HttpRequestMethodConfig.Values)}
		case c.SourceIpConfig != nil:
			cond["source_ip"] = map[string]any{"values": toAny(c.SourceIpConfig.Values)}
		case c.HttpHeaderConfig != nil:
			cond["http_header"] = map[string]any{
				"http_header_name": aws.ToString(c.HttpHeaderConfig.HttpHeaderName),
				"values":           toAny(c.HttpHeaderConfig.Values),
			}
		case c.QueryStringConfig != nil:
			var pairs []any
			for _, kv := range c.QueryStringConfig.Values {
				pairs = append(pairs, map[string]any{"key": aws.ToString(kv.Key), "value": aws.ToString(kv.Value)})
			}
			cond["query_string"] = pairs
		default:
			continue
		}
		out = append(out, cond)
	}
	return out
}

func lbActions(as []elbtypes.Action) []any {
	var out []any
	for _, a := range as {
		act := map[string]any{"type": string(a.Type)}
		switch a.Type {
		case elbtypes.ActionTypeEnumForward:
			act = lbForward(a, act)
		case elbtypes.ActionTypeEnumRedirect:
			if rc := a.RedirectConfig; rc != nil {
				red := map[string]any{"status_code": string(rc.StatusCode)}
				for k, v := range map[string]string{
					"host": aws.ToString(rc.Host), "path": aws.ToString(rc.Path),
					"port": aws.ToString(rc.Port), "protocol": aws.ToString(rc.Protocol),
					"query": aws.ToString(rc.Query),
				} {
					if v != "" {
						red[k] = v
					}
				}
				act["redirect"] = red
			}
		case elbtypes.ActionTypeEnumFixedResponse:
			if fr := a.FixedResponseConfig; fr != nil {
				f := map[string]any{"status_code": aws.ToString(fr.StatusCode)}
				if v := aws.ToString(fr.ContentType); v != "" {
					f["content_type"] = v
				}
				if v := aws.ToString(fr.MessageBody); v != "" {
					f["message_body"] = v
				}
				act["fixed_response"] = f
			}
		}
		out = append(out, act)
	}
	return out
}

// Always emit forward; floor stickiness duration to 1.
func lbForward(a elbtypes.Action, act map[string]any) map[string]any {
	fc := a.ForwardConfig
	if fc == nil {
		act["target_group_arn"] = aws.ToString(a.TargetGroupArn)
		return act
	}

	if len(fc.TargetGroups) == 1 {
		act["target_group_arn"] = aws.ToString(fc.TargetGroups[0].TargetGroupArn)
	}

	var tgs []any
	for _, tg := range fc.TargetGroups {
		m := map[string]any{"arn": aws.ToString(tg.TargetGroupArn)}
		if tg.Weight != nil {
			m["weight"] = *tg.Weight
		}
		tgs = append(tgs, m)
	}
	dur, enabled := int32(1), false
	if sc := fc.TargetGroupStickinessConfig; sc != nil {
		enabled = aws.ToBool(sc.Enabled)
		if sc.DurationSeconds != nil && *sc.DurationSeconds > 0 {
			dur = *sc.DurationSeconds
		}
	}
	act["forward"] = map[string]any{
		"target_group": tgs,
		"stickiness":   map[string]any{"enabled": enabled, "duration": dur},
	}
	return act
}
