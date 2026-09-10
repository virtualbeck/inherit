package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53rtypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_route53_resolver_firewall_rule_group", hydrateR53RFirewallRuleGroup)
	registerFanout("aws_route53_resolver_firewall_rule_group", fanoutR53RFirewallRules)
	register("aws_route53_resolver_firewall_domain_list", hydrateR53RFirewallDomainList)
	register("aws_route53_resolver_query_log_config", hydrateR53RQueryLogConfig)
	registerFanout("aws_route53_resolver_query_log_config", fanoutR53RQueryLogConfigAssociations)
}

func hydrateR53RFirewallRuleGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := route53resolver.NewFromConfig(c.Cfg(r.Region)).GetFirewallRuleGroup(ctx, &route53resolver.GetFirewallRuleGroupInput{FirewallRuleGroupId: &id})
	if err != nil {
		return nil, err
	}
	g := out.FirewallRuleGroup
	if g == nil {
		return nil, fmt.Errorf("not found")
	}
	return map[string]any{"name": aws.ToString(g.Name)}, nil
}

func hydrateR53RFirewallDomainList(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := route53resolver.NewFromConfig(c.Cfg(r.Region))
	id := r.ID
	out, err := cl.GetFirewallDomainList(ctx, &route53resolver.GetFirewallDomainListInput{FirewallDomainListId: &id})
	if err != nil {
		return nil, err
	}
	l := out.FirewallDomainList
	if l == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"name": aws.ToString(l.Name)}

	var domains []string
	token := (*string)(nil)
	for {
		page, derr := cl.ListFirewallDomains(ctx, &route53resolver.ListFirewallDomainsInput{FirewallDomainListId: &id, NextToken: token})
		if derr != nil {
			break
		}
		domains = append(domains, page.Domains...)
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	if len(domains) > 0 {
		cfg["domains"] = toAny(domains)
	}
	return cfg, nil
}

func hydrateR53RQueryLogConfig(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := route53resolver.NewFromConfig(c.Cfg(r.Region)).GetResolverQueryLogConfig(ctx, &route53resolver.GetResolverQueryLogConfigInput{ResolverQueryLogConfigId: &id})
	if err != nil {
		return nil, err
	}
	q := out.ResolverQueryLogConfig
	if q == nil {
		return nil, fmt.Errorf("not found")
	}
	return map[string]any{
		"name":            aws.ToString(q.Name),
		"destination_arn": aws.ToString(q.DestinationArn),
	}, nil
}

// fanoutR53RFirewallRules expands a rule group into its individual rules and
// any VPC associations, each a separate top-level resource in the provider.
func fanoutR53RFirewallRules(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := route53resolver.NewFromConfig(c.Cfg(parent.Region))
	groupID := parent.ID
	var kids []model.Resource

	token := (*string)(nil)
	for {
		page, err := cl.ListFirewallRules(ctx, &route53resolver.ListFirewallRulesInput{FirewallRuleGroupId: &groupID, NextToken: token})
		if err != nil {
			return kids, err
		}
		for _, fr := range page.FirewallRules {
			domainListID := aws.ToString(fr.FirewallDomainListId)
			id := groupID + ":" + domainListID
			cfg := map[string]any{
				"name":                    aws.ToString(fr.Name),
				"firewall_rule_group_id":  groupID,
				"firewall_domain_list_id": domainListID,
				"priority":                aws.ToInt32(fr.Priority),
				"action":                  string(fr.Action),
			}
			if v := string(fr.BlockResponse); v != "" {
				cfg["block_response"] = v
			}
			if v := string(fr.BlockOverrideDnsType); v != "" {
				cfg["block_override_dns_type"] = v
			}
			if v := aws.ToString(fr.BlockOverrideDomain); v != "" {
				cfg["block_override_domain"] = v
			}
			if fr.BlockOverrideTtl != nil {
				cfg["block_override_ttl"] = aws.ToInt32(fr.BlockOverrideTtl)
			}
			kids = append(kids, model.Resource{
				Service: "route53resolver", Type: "firewall-rule", TFType: "aws_route53_resolver_firewall_rule",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}

	assocToken := (*string)(nil)
	for {
		page, err := cl.ListFirewallRuleGroupAssociations(ctx, &route53resolver.ListFirewallRuleGroupAssociationsInput{
			FirewallRuleGroupId: &groupID, NextToken: assocToken,
		})
		if err != nil {
			return kids, err
		}
		for _, a := range page.FirewallRuleGroupAssociations {
			id := aws.ToString(a.Id)
			if id == "" {
				continue
			}
			cfg := map[string]any{
				"name":                   aws.ToString(a.Name),
				"firewall_rule_group_id": groupID,
				"vpc_id":                 aws.ToString(a.VpcId),
				"priority":               aws.ToInt32(a.Priority),
			}
			if v := string(a.MutationProtection); v != "" {
				cfg["mutation_protection"] = v
			}
			// FirewallRuleGroupAssociation carries no Tags field at all --
			// confirmed by a real fresh import dropping every tag, not
			// assumed. A separate ListTagsForResource(arn) call is the
			// only way to get them.
			var tags map[string]string
			if arn := aws.ToString(a.Arn); arn != "" {
				if lt, terr := cl.ListTagsForResource(ctx, &route53resolver.ListTagsForResourceInput{ResourceArn: &arn}); terr == nil {
					tags = make(map[string]string, len(lt.Tags))
					for _, t := range lt.Tags {
						if k := aws.ToString(t.Key); k != "" {
							tags[k] = aws.ToString(t.Value)
						}
					}
					if len(tags) > 0 {
						cfg["tags"] = tags
					} else {
						tags = nil
					}
				}
			}
			kids = append(kids, model.Resource{
				Service: "route53resolver", Type: "firewall-rule-group-association", TFType: "aws_route53_resolver_firewall_rule_group_association",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Tags:   tags,
				Config: cfg,
			})
		}
		if page.NextToken == nil {
			break
		}
		assocToken = page.NextToken
	}

	return kids, nil
}

// fanoutR53RQueryLogConfigAssociations expands a query log config into its
// VPC associations.
func fanoutR53RQueryLogConfigAssociations(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := route53resolver.NewFromConfig(c.Cfg(parent.Region))
	configID := parent.ID
	var kids []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.ListResolverQueryLogConfigAssociations(ctx, &route53resolver.ListResolverQueryLogConfigAssociationsInput{
			Filters:   []r53rtypes.Filter{{Name: aws.String("ResolverQueryLogConfigId"), Values: []string{configID}}},
			NextToken: token,
		})
		if err != nil {
			return kids, err
		}
		for _, a := range page.ResolverQueryLogConfigAssociations {
			id := aws.ToString(a.Id)
			if id == "" {
				continue
			}
			kids = append(kids, model.Resource{
				Service: "route53resolver", Type: "query-log-config-association", TFType: "aws_route53_resolver_query_log_config_association",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: map[string]any{
					"resolver_query_log_config_id": configID,
					"resource_id":                  aws.ToString(a.ResourceId),
				},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return kids, nil
}
