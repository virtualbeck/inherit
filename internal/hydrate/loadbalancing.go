package hydrate

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_lb", hydrateLB)
	register("aws_lb_target_group", hydrateTargetGroup)
	register("aws_lb_listener", hydrateListener)
}

func hydrateLB(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_lb")
	if err != nil {
		return nil, err
	}
	cl := elb.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{LoadBalancerArns: []string{r.ARN}})
	if err != nil {
		return nil, err
	}
	if len(out.LoadBalancers) == 0 {
		return nil, fmt.Errorf("not found")
	}
	lb := out.LoadBalancers[0]
	cfg, err := Generic(lb, sch, nil)
	if err != nil {
		return nil, err
	}
	delete(cfg, "scheme")
	delete(cfg, "type")
	cfg["internal"] = string(lb.Scheme) == "internal"
	cfg["load_balancer_type"] = string(lb.Type)
	cfg["name"] = aws.ToString(lb.LoadBalancerName)

	var subnets, sgs []any
	for _, az := range lb.AvailabilityZones {
		subnets = append(subnets, aws.ToString(az.SubnetId))
	}
	for _, g := range lb.SecurityGroups {
		sgs = append(sgs, g)
	}
	if len(subnets) > 0 {
		cfg["subnets"] = subnets
	}
	if len(sgs) > 0 {
		cfg["security_groups"] = sgs
	}
	delete(cfg, "availability_zones")
	delete(cfg, "vpc_id") // computed

	// DescribeLoadBalancers doesn't carry these -- they're a separate
	// per-LB attribute bag the provider reads on every plan. Only map the
	// common boolean/int ones with a direct schema attribute; anything
	// unrecognized (access_logs.*, ipv6 settings, etc.) is left alone.
	if attrs, aerr := cl.DescribeLoadBalancerAttributes(ctx, &elb.DescribeLoadBalancerAttributesInput{LoadBalancerArn: &r.ARN}); aerr == nil {
		for _, a := range attrs.Attributes {
			k, v := aws.ToString(a.Key), aws.ToString(a.Value)
			switch k {
			case "deletion_protection.enabled":
				cfg["enable_deletion_protection"] = v == "true"
			case "idle_timeout.timeout_seconds":
				if n, err := strconv.Atoi(v); err == nil {
					cfg["idle_timeout"] = n
				}
			case "routing.http2.enabled":
				cfg["enable_http2"] = v == "true"
			case "routing.http.drop_invalid_header_fields.enabled":
				cfg["drop_invalid_header_fields"] = v == "true"
			case "routing.http.preserve_host_header.enabled":
				cfg["preserve_host_header"] = v == "true"
			case "routing.http.desync_mitigation_mode":
				cfg["desync_mitigation_mode"] = v
			case "load_balancing.cross_zone.enabled":
				if v == "true" || v == "false" {
					cfg["enable_cross_zone_load_balancing"] = v == "true"
				}
			case "waf.fail_open.enabled":
				cfg["enable_waf_fail_open"] = v == "true"
			}
		}
	}
	return cfg, nil
}

func hydrateListener(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := elb.NewFromConfig(c.Cfg(r.Region)).DescribeListeners(ctx, &elb.DescribeListenersInput{
		ListenerArns: []string{r.ARN},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Listeners) == 0 {
		return nil, fmt.Errorf("not found")
	}
	l := out.Listeners[0]
	cfg := map[string]any{
		"load_balancer_arn": aws.ToString(l.LoadBalancerArn),
		"port":              aws.ToInt32(l.Port),
		"protocol":          string(l.Protocol),
	}
	if v := aws.ToString(l.SslPolicy); v != "" {
		cfg["ssl_policy"] = v
	}
	// the listener's own default certificate; additional SNI certs are
	// separate aws_lb_listener_certificate resources (fanoutListenerRules).
	if len(l.Certificates) > 0 {
		if v := aws.ToString(l.Certificates[0].CertificateArn); v != "" {
			cfg["certificate_arn"] = v
		}
	}
	// reuse the same action builder as fanoutListenerRules (aws_lb_rules.go)
	// so a simple single-target-group forward carries the same
	// target_group_arn form, and anything else (weighted/sticky forwards,
	// redirect, fixed-response) gets its full nested block.
	if acts := lbActions(l.DefaultActions); len(acts) > 0 {
		cfg["default_action"] = acts
	}
	return cfg, nil
}

func hydrateTargetGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_lb_target_group")
	if err != nil {
		return nil, err
	}
	out, err := elb.NewFromConfig(c.Cfg(r.Region)).DescribeTargetGroups(ctx, &elb.DescribeTargetGroupsInput{
		TargetGroupArns: []string{r.ARN},
	})
	if err != nil {
		return nil, err
	}
	if len(out.TargetGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	tg := out.TargetGroups[0]
	cfg, err := Generic(tg, sch, nil)
	if err != nil {
		return nil, err
	}
	cfg["name"] = aws.ToString(tg.TargetGroupName)
	return cfg, nil
}
