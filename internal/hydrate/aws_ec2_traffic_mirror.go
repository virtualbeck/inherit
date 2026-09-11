package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_ec2_traffic_mirror_filter", hydrateTrafficMirrorFilter)
	registerFanout("aws_ec2_traffic_mirror_filter", fanoutTrafficMirrorFilterRules)
	register("aws_ec2_traffic_mirror_session", hydrateTrafficMirrorSession)
	register("aws_ec2_traffic_mirror_target", hydrateTrafficMirrorTarget)
}

func hydrateTrafficMirrorFilter(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTrafficMirrorFilters(ctx, &ec2.DescribeTrafficMirrorFiltersInput{TrafficMirrorFilterIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.TrafficMirrorFilters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	f := out.TrafficMirrorFilters[0]
	cfg := map[string]any{}
	if v := aws.ToString(f.Description); v != "" {
		cfg["description"] = v
	}
	if len(f.NetworkServices) > 0 {
		svcs := make([]string, len(f.NetworkServices))
		for i, s := range f.NetworkServices {
			svcs[i] = string(s)
		}
		cfg["network_services"] = toAny(svcs)
	}
	if len(f.Tags) > 0 {
		cfg["tags"] = ec2TagMap(f.Tags)
	}
	return cfg, nil
}

// fanoutTrafficMirrorFilterRules expands a filter into its ingress/egress
// rules -- DescribeTrafficMirrorFilters already returns both lists directly
// on the filter itself, no separate call needed.
func fanoutTrafficMirrorFilterRules(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	id := parent.ID
	out, err := ec2.NewFromConfig(c.Cfg(parent.Region)).DescribeTrafficMirrorFilters(ctx, &ec2.DescribeTrafficMirrorFiltersInput{TrafficMirrorFilterIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.TrafficMirrorFilters) == 0 {
		return nil, nil
	}
	f := out.TrafficMirrorFilters[0]
	var kids []model.Resource
	rules := append(append([]ec2types.TrafficMirrorFilterRule{}, f.IngressFilterRules...), f.EgressFilterRules...)
	for _, rule := range rules {
		ruleID := aws.ToString(rule.TrafficMirrorFilterRuleId)
		if ruleID == "" {
			continue
		}
		cfg := map[string]any{
			"traffic_mirror_filter_id": id,
			"destination_cidr_block":   aws.ToString(rule.DestinationCidrBlock),
			"source_cidr_block":        aws.ToString(rule.SourceCidrBlock),
			"rule_action":              string(rule.RuleAction),
			"rule_number":              int(aws.ToInt32(rule.RuleNumber)),
			"traffic_direction":        string(rule.TrafficDirection),
		}
		if v := aws.ToString(rule.Description); v != "" {
			cfg["description"] = v
		}
		if rule.Protocol != nil {
			cfg["protocol"] = int(*rule.Protocol)
		}
		if pr := rule.DestinationPortRange; pr != nil {
			cfg["destination_port_range"] = []any{trafficMirrorPortRange(pr)}
		}
		if pr := rule.SourcePortRange; pr != nil {
			cfg["source_port_range"] = []any{trafficMirrorPortRange(pr)}
		}
		kids = append(kids, model.Resource{
			Service: "ec2", Type: "traffic-mirror-filter-rule", TFType: "aws_ec2_traffic_mirror_filter_rule",
			Region: parent.Region, Account: parent.Account,
			ID: ruleID,
			// the resource's own stored state id is just the bare rule id,
			// but its ImportStateContext expects "filter-id:rule-id" as the
			// import input specifically -- confirmed by a real "unexpected
			// format ... expected <filter-id>:<rule-id>" failure, not
			// assumed from the bare-id convention most other types use.
			ImportID: id + ":" + ruleID,
			Config:   cfg,
		})
	}
	return kids, nil
}

func trafficMirrorPortRange(pr *ec2types.TrafficMirrorPortRange) map[string]any {
	m := map[string]any{}
	if pr.FromPort != nil {
		m["from_port"] = int(*pr.FromPort)
	}
	if pr.ToPort != nil {
		m["to_port"] = int(*pr.ToPort)
	}
	return m
}

func hydrateTrafficMirrorSession(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTrafficMirrorSessions(ctx, &ec2.DescribeTrafficMirrorSessionsInput{TrafficMirrorSessionIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.TrafficMirrorSessions) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.TrafficMirrorSessions[0]
	cfg := map[string]any{
		"network_interface_id":     aws.ToString(s.NetworkInterfaceId),
		"traffic_mirror_filter_id": aws.ToString(s.TrafficMirrorFilterId),
		"traffic_mirror_target_id": aws.ToString(s.TrafficMirrorTargetId),
		"session_number":           int(aws.ToInt32(s.SessionNumber)),
	}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	if s.PacketLength != nil {
		cfg["packet_length"] = int(*s.PacketLength)
	}
	if s.VirtualNetworkId != nil {
		cfg["virtual_network_id"] = int(*s.VirtualNetworkId)
	}
	if len(s.Tags) > 0 {
		cfg["tags"] = ec2TagMap(s.Tags)
	}
	return cfg, nil
}

func hydrateTrafficMirrorTarget(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTrafficMirrorTargets(ctx, &ec2.DescribeTrafficMirrorTargetsInput{TrafficMirrorTargetIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.TrafficMirrorTargets) == 0 {
		return nil, fmt.Errorf("not found")
	}
	t := out.TrafficMirrorTargets[0]
	cfg := map[string]any{}
	if v := aws.ToString(t.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(t.NetworkInterfaceId); v != "" {
		cfg["network_interface_id"] = v
	}
	if v := aws.ToString(t.NetworkLoadBalancerArn); v != "" {
		cfg["network_load_balancer_arn"] = v
	}
	if v := aws.ToString(t.GatewayLoadBalancerEndpointId); v != "" {
		cfg["gateway_load_balancer_endpoint_id"] = v
	}
	if len(t.Tags) > 0 {
		cfg["tags"] = ec2TagMap(t.Tags)
	}
	return cfg, nil
}
