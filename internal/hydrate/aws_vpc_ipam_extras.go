package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_vpc_ipam_pool", hydrateIPAMPool)
	registerFanout("aws_vpc_ipam_pool", fanoutIPAMPoolCIDRs)
	register("aws_vpc_ipam_scope", hydrateIPAMScope)
	register("aws_vpc_ipam_resource_discovery", hydrateIPAMResourceDiscovery)
	register("aws_vpc_ipam_resource_discovery_association", hydrateIPAMResourceDiscoveryAssociation)
}

// ipamArnID extracts the trailing id segment off an "arn:...:ipam-x/id"
// style ARN -- several IPAM sub-resources only carry the parent's ARN, not
// its bare id, in their own Describe response.
func ipamArnID(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return ""
}

func hydrateIPAMPool(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeIpamPools(ctx, &ec2.DescribeIpamPoolsInput{IpamPoolIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.IpamPools) == 0 {
		return nil, fmt.Errorf("not found")
	}
	p := out.IpamPools[0]
	cfg := map[string]any{
		"address_family": string(p.AddressFamily),
		"ipam_scope_id":  ipamArnID(aws.ToString(p.IpamScopeArn)),
	}
	if v := aws.ToString(p.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(p.Locale); v != "" {
		cfg["locale"] = v
	}
	if v := string(p.AwsService); v != "" {
		cfg["aws_service"] = v
	}
	if v := string(p.PublicIpSource); v != "" {
		cfg["public_ip_source"] = v
	}
	if p.AutoImport != nil {
		cfg["auto_import"] = *p.AutoImport
	}
	if p.PubliclyAdvertisable != nil {
		cfg["publicly_advertisable"] = *p.PubliclyAdvertisable
	}
	if p.AllocationDefaultNetmaskLength != nil {
		cfg["allocation_default_netmask_length"] = int(*p.AllocationDefaultNetmaskLength)
	}
	if p.AllocationMaxNetmaskLength != nil {
		cfg["allocation_max_netmask_length"] = int(*p.AllocationMaxNetmaskLength)
	}
	if p.AllocationMinNetmaskLength != nil {
		cfg["allocation_min_netmask_length"] = int(*p.AllocationMinNetmaskLength)
	}
	if v := aws.ToString(p.SourceIpamPoolId); v != "" {
		cfg["source_ipam_pool_id"] = v
	}
	if len(p.AllocationResourceTags) > 0 {
		m := make(map[string]string, len(p.AllocationResourceTags))
		for _, t := range p.AllocationResourceTags {
			if k := aws.ToString(t.Key); k != "" {
				m[k] = aws.ToString(t.Value)
			}
		}
		cfg["allocation_resource_tags"] = m
	}
	if len(p.Tags) > 0 {
		cfg["tags"] = ec2TagMap(p.Tags)
	}
	return cfg, nil
}

// fanoutIPAMPoolCIDRs expands a pool into its provisioned CIDR blocks.
func fanoutIPAMPoolCIDRs(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := ec2.NewFromConfig(c.Cfg(parent.Region))
	poolID := parent.ID
	var kids []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.GetIpamPoolCidrs(ctx, &ec2.GetIpamPoolCidrsInput{IpamPoolId: &poolID, NextToken: token})
		if err != nil {
			return kids, err
		}
		for _, pc := range page.IpamPoolCidrs {
			cidr := aws.ToString(pc.Cidr)
			if cidr == "" {
				continue
			}
			id := cidr + "_" + poolID
			kids = append(kids, model.Resource{
				Service: "ec2", Type: "ipam-pool-cidr", TFType: "aws_vpc_ipam_pool_cidr",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: map[string]any{"ipam_pool_id": poolID, "cidr": cidr},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return kids, nil
}

func hydrateIPAMScope(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeIpamScopes(ctx, &ec2.DescribeIpamScopesInput{IpamScopeIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.IpamScopes) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.IpamScopes[0]
	cfg := map[string]any{"ipam_id": ipamArnID(aws.ToString(s.IpamArn))}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	if len(s.Tags) > 0 {
		cfg["tags"] = ec2TagMap(s.Tags)
	}
	return cfg, nil
}

func hydrateIPAMResourceDiscovery(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeIpamResourceDiscoveries(ctx, &ec2.DescribeIpamResourceDiscoveriesInput{IpamResourceDiscoveryIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.IpamResourceDiscoveries) == 0 {
		return nil, fmt.Errorf("not found")
	}
	d := out.IpamResourceDiscoveries[0]
	cfg := map[string]any{}
	if v := aws.ToString(d.Description); v != "" {
		cfg["description"] = v
	}
	// Required, min 1 -- confirmed by a real tofu validate failure when
	// this was left out (the schema list wasn't checked for block_types,
	// only top-level attributes, on the first pass).
	if len(d.OperatingRegions) > 0 {
		var regions []any
		for _, or := range d.OperatingRegions {
			if v := aws.ToString(or.RegionName); v != "" {
				regions = append(regions, map[string]any{"region_name": v})
			}
		}
		cfg["operating_regions"] = regions
	}
	if len(d.Tags) > 0 {
		cfg["tags"] = ec2TagMap(d.Tags)
	}
	return cfg, nil
}

func hydrateIPAMResourceDiscoveryAssociation(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeIpamResourceDiscoveryAssociations(ctx, &ec2.DescribeIpamResourceDiscoveryAssociationsInput{
		IpamResourceDiscoveryAssociationIds: []string{id},
	})
	if err != nil {
		return nil, err
	}
	if len(out.IpamResourceDiscoveryAssociations) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.IpamResourceDiscoveryAssociations[0]
	cfg := map[string]any{
		"ipam_id":                    ipamArnID(aws.ToString(a.IpamArn)),
		"ipam_resource_discovery_id": aws.ToString(a.IpamResourceDiscoveryId),
	}
	if len(a.Tags) > 0 {
		cfg["tags"] = ec2TagMap(a.Tags)
	}
	return cfg, nil
}
