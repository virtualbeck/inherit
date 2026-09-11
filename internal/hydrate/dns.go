package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_route53_zone", hydrateRoute53Zone)
	register("aws_route53_resolver_endpoint", hydrateResolverEndpoint)
	register("aws_route53_resolver_rule", hydrateResolverRule)
	register("aws_route53_health_check", hydrateHealthCheck)
}

func hydrateRoute53Zone(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID // "hostedzone/Z123" or "Z123"
	if i := lastSlash(id); i >= 0 {
		id = id[i+1:]
	}
	out, err := route53.NewFromConfig(c.Cfg("")).GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.HostedZone.Name)}
	if out.HostedZone.Config != nil {
		if d := aws.ToString(out.HostedZone.Config.Comment); d != "" {
			cfg["comment"] = d
		}
	}
	// GetHostedZone returns the associated VPCs directly (private zones
	// only) -- omitting them isn't just an empty diff, it's the provider
	// reading real associations back and finding config declares none.
	var vpcs []any
	for _, v := range out.VPCs {
		vpcs = append(vpcs, map[string]any{
			"vpc_id":     aws.ToString(v.VPCId),
			"vpc_region": string(v.VPCRegion),
		})
	}
	if len(vpcs) > 0 {
		cfg["vpc"] = vpcs
	}
	return cfg, nil
}

func hydrateResolverEndpoint(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := route53resolver.NewFromConfig(c.Cfg(r.Region)).GetResolverEndpoint(ctx, &route53resolver.GetResolverEndpointInput{ResolverEndpointId: &id})
	if err != nil {
		return nil, err
	}
	e := out.ResolverEndpoint
	cfg := map[string]any{
		"direction": string(e.Direction),
	}
	if v := aws.ToString(e.Name); v != "" {
		cfg["name"] = v
	}
	if len(e.SecurityGroupIds) > 0 {
		cfg["security_group_ids"] = toAny(e.SecurityGroupIds)
	}
	ips, err := route53resolver.NewFromConfig(c.Cfg(r.Region)).ListResolverEndpointIpAddresses(ctx, &route53resolver.ListResolverEndpointIpAddressesInput{ResolverEndpointId: &id})
	if err == nil {
		var addrs []any
		for _, a := range ips.IpAddresses {
			m := map[string]any{"subnet_id": aws.ToString(a.SubnetId)}
			if v := aws.ToString(a.Ip); v != "" {
				m["ip"] = v
			}
			addrs = append(addrs, m)
		}
		if len(addrs) > 0 {
			cfg["ip_address"] = addrs
		}
	}
	return cfg, nil
}

func hydrateResolverRule(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := route53resolver.NewFromConfig(c.Cfg(r.Region)).GetResolverRule(ctx, &route53resolver.GetResolverRuleInput{ResolverRuleId: &id})
	if err != nil {
		return nil, err
	}
	rr := out.ResolverRule
	cfg := map[string]any{
		"domain_name": aws.ToString(rr.DomainName),
		"rule_type":   string(rr.RuleType),
	}
	if v := aws.ToString(rr.Name); v != "" {
		cfg["name"] = v
	}
	if v := aws.ToString(rr.ResolverEndpointId); v != "" {
		cfg["resolver_endpoint_id"] = v
	}
	var ips []any
	for _, t := range rr.TargetIps {
		m := map[string]any{"ip": aws.ToString(t.Ip)}
		if t.Port != nil {
			m["port"] = *t.Port
		}
		ips = append(ips, m)
	}
	if len(ips) > 0 {
		cfg["target_ip"] = ips
	}
	return cfg, nil
}

func hydrateHealthCheck(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := route53.NewFromConfig(c.Cfg("")).GetHealthCheck(ctx, &route53.GetHealthCheckInput{HealthCheckId: &r.ID})
	if err != nil {
		return nil, err
	}
	hc := out.HealthCheck.HealthCheckConfig
	cfg := map[string]any{"type": string(hc.Type)}
	for k, v := range map[string]string{
		"fqdn":          aws.ToString(hc.FullyQualifiedDomainName),
		"ip_address":    aws.ToString(hc.IPAddress),
		"resource_path": aws.ToString(hc.ResourcePath),
		"search_string": aws.ToString(hc.SearchString),
	} {
		if v != "" {
			cfg[k] = v
		}
	}
	if hc.Port != nil {
		cfg["port"] = *hc.Port
	}
	if hc.FailureThreshold != nil {
		cfg["failure_threshold"] = *hc.FailureThreshold
	}
	if hc.RequestInterval != nil {
		cfg["request_interval"] = *hc.RequestInterval
	}
	// a CALCULATED or CLOUDWATCH_METRIC health check has nothing else
	// recoverable at all without its type-specific fields below.
	if hc.Disabled != nil {
		cfg["disabled"] = *hc.Disabled
	}
	if hc.Inverted != nil {
		cfg["invert_healthcheck"] = *hc.Inverted
	}
	if hc.MeasureLatency != nil {
		cfg["measure_latency"] = *hc.MeasureLatency
	}
	if hc.EnableSNI != nil {
		cfg["enable_sni"] = *hc.EnableSNI
	}
	if v := string(hc.InsufficientDataHealthStatus); v != "" {
		cfg["insufficient_data_health_status"] = v
	}
	if hc.HealthThreshold != nil {
		cfg["child_health_threshold"] = *hc.HealthThreshold
	}
	if len(hc.ChildHealthChecks) > 0 {
		cfg["child_healthchecks"] = toAny(hc.ChildHealthChecks)
	}
	if len(hc.Regions) > 0 {
		var regs []any
		for _, reg := range hc.Regions {
			regs = append(regs, string(reg))
		}
		cfg["regions"] = regs
	}
	if v := aws.ToString(hc.RoutingControlArn); v != "" {
		cfg["routing_control_arn"] = v
	}
	if ai := hc.AlarmIdentifier; ai != nil {
		if v := aws.ToString(ai.Name); v != "" {
			cfg["cloudwatch_alarm_name"] = v
		}
		cfg["cloudwatch_alarm_region"] = string(ai.Region)
	}
	return cfg, nil
}
