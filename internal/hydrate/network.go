package hydrate

import (
	"context"
	"encoding/xml"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_vpc", hydrateVPC)
	register("aws_subnet", hydrateSubnet)
	register("aws_security_group", hydrateSecurityGroup)
	register("aws_internet_gateway", hydrateIGW)
	register("aws_nat_gateway", hydrateNAT)
	register("aws_eip", hydrateEIP)
	register("aws_route_table", hydrateRouteTable)
	register("aws_ec2_transit_gateway", hydrateTGW)
	register("aws_ec2_transit_gateway_vpc_attachment", hydrateTGWAttach)
	register("aws_ec2_transit_gateway_route_table", hydrateTGWRouteTable)
	register("aws_vpn_gateway", hydrateVPNGateway)
	register("aws_customer_gateway", hydrateCustomerGateway)
	register("aws_vpn_connection", hydrateVPNConnection)
	register("aws_vpc_endpoint", hydrateVPCEndpoint)
	register("aws_vpc_dhcp_options", hydrateDHCPOptions)
	register("aws_network_acl", hydrateNetworkACL)
	register("aws_ec2_network_insights_path", genericHydrator("aws_ec2_network_insights_path", fetchNetworkInsightsPath))
	register("aws_key_pair", hydrateKeyPair)
	register("aws_ebs_volume", hydrateEBSVolume)
	register("aws_flow_log", hydrateFlowLog)
	register("aws_ec2_managed_prefix_list", hydrateManagedPrefixList)
	register("aws_vpc_peering_connection", hydrateVPCPeering)
	register("aws_network_interface", hydrateNetworkInterface)
	register("aws_dx_connection", hydrateDXConnection)
	register("aws_dx_gateway", hydrateDXGateway)
	register("aws_networkfirewall_firewall", hydrateNetworkFirewall)
}

func hydrateVPC(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_vpc")
	if err != nil {
		return nil, err
	}
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.Vpcs) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cfg, err := Generic(out.Vpcs[0], sch, nil)
	if err != nil {
		return nil, err
	}
	// enable_dns_support/enable_dns_hostnames/enable_network_address_usage_metrics
	// aren't part of DescribeVpcs at all -- each needs its own
	// DescribeVpcAttribute call (one VpcAttributeName per call, same
	// per-attribute quirk as instance attributes). enable_dns_support in
	// particular is Optional with no Computed fallback in the schema, so
	// leaving it unset here would show a permanent diff against the real
	// value (which defaults to true, not false).
	ec2c := ec2.NewFromConfig(c.Cfg(r.Region))
	if attr, aerr := ec2c.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId: &r.ID, Attribute: ec2types.VpcAttributeNameEnableDnsSupport,
	}); aerr == nil && attr.EnableDnsSupport != nil && attr.EnableDnsSupport.Value != nil {
		cfg["enable_dns_support"] = *attr.EnableDnsSupport.Value
	}
	if attr, aerr := ec2c.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId: &r.ID, Attribute: ec2types.VpcAttributeNameEnableDnsHostnames,
	}); aerr == nil && attr.EnableDnsHostnames != nil && attr.EnableDnsHostnames.Value != nil {
		cfg["enable_dns_hostnames"] = *attr.EnableDnsHostnames.Value
	}
	if attr, aerr := ec2c.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId: &r.ID, Attribute: ec2types.VpcAttributeNameEnableNetworkAddressUsageMetrics,
	}); aerr == nil && attr.EnableNetworkAddressUsageMetrics != nil && attr.EnableNetworkAddressUsageMetrics.Value != nil {
		cfg["enable_network_address_usage_metrics"] = *attr.EnableNetworkAddressUsageMetrics.Value
	}
	if aws.ToBool(out.Vpcs[0].IsDefault) {
		// AWS creates exactly one of these per region automatically; the
		// provider models it as a wholly different resource type
		// (aws_default_vpc) that ADOPTS the existing VPC rather than
		// creating one, and almost everything about it -- cidr_block,
		// instance_tenancy, dhcp_options_id, the default route/network
		// ACL ids -- is Computed-only there, unlike the same names on
		// plain aws_vpc. Only carry forward the handful of fields still
		// settable on both.
		dcfg := map[string]any{retypeSentinel: "aws_default_vpc"}
		for _, k := range []string{"tags", "enable_dns_support", "enable_dns_hostnames", "enable_network_address_usage_metrics"} {
			if v, ok := cfg[k]; ok {
				dcfg[k] = v
			}
		}
		return dcfg, nil
	}
	return cfg, nil
}

func hydrateSubnet(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.Subnets) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.Subnets[0]
	// Explicit field pick: Generic() would also emit availability_zone_id (which
	// conflicts with availability_zone) and lone outpost-only args.
	cfg := map[string]any{"vpc_id": aws.ToString(s.VpcId)}
	if v := aws.ToString(s.CidrBlock); v != "" {
		cfg["cidr_block"] = v
	}
	if v := aws.ToString(s.AvailabilityZone); v != "" {
		cfg["availability_zone"] = v
	}
	if s.MapPublicIpOnLaunch != nil {
		cfg["map_public_ip_on_launch"] = *s.MapPublicIpOnLaunch
	}
	if s.AssignIpv6AddressOnCreation != nil && *s.AssignIpv6AddressOnCreation {
		cfg["assign_ipv6_address_on_creation"] = true
	}
	for _, a := range s.Ipv6CidrBlockAssociationSet {
		if a.Ipv6CidrBlock != nil {
			cfg["ipv6_cidr_block"] = aws.ToString(a.Ipv6CidrBlock)
		}
	}
	if o := s.PrivateDnsNameOptionsOnLaunch; o != nil {
		if v := string(o.HostnameType); v != "" {
			cfg["private_dns_hostname_type_on_launch"] = v
		}
		if o.EnableResourceNameDnsARecord != nil && *o.EnableResourceNameDnsARecord {
			cfg["enable_resource_name_dns_a_record_on_launch"] = true
		}
		if o.EnableResourceNameDnsAAAARecord != nil && *o.EnableResourceNameDnsAAAARecord {
			cfg["enable_resource_name_dns_aaaa_record_on_launch"] = true
		}
	}
	if s.EnableDns64 != nil && *s.EnableDns64 {
		cfg["enable_dns64"] = true
	}
	if v := aws.ToString(s.OutpostArn); v != "" {
		cfg["outpost_arn"] = v
	}
	if s.Ipv6Native != nil && *s.Ipv6Native {
		cfg["ipv6_native"] = true
	}
	if s.EnableLniAtDeviceIndex != nil {
		cfg["enable_lni_at_device_index"] = *s.EnableLniAtDeviceIndex
	}
	if v := aws.ToString(s.CustomerOwnedIpv4Pool); v != "" {
		cfg["customer_owned_ipv4_pool"] = v
	}
	if s.MapCustomerOwnedIpOnLaunch != nil && *s.MapCustomerOwnedIpOnLaunch {
		cfg["map_customer_owned_ip_on_launch"] = true
	}
	return cfg, nil
}

// The security group shell only. Rules come as separate
// aws_vpc_security_group_ingress_rule / _egress_rule resources (the provider v6
// direction); those get their own hydrator.
func hydrateSecurityGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.SecurityGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.SecurityGroups[0]
	cfg := map[string]any{
		"name":        aws.ToString(g.GroupName),
		"description": aws.ToString(g.Description),
	}
	if v := aws.ToString(g.VpcId); v != "" {
		cfg["vpc_id"] = v
	}
	return cfg, nil
}

func hydrateIGW(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		InternetGatewayIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.InternetGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{}
	if a := out.InternetGateways[0].Attachments; len(a) > 0 {
		cfg["vpc_id"] = aws.ToString(a[0].VpcId)
	}
	return cfg, nil
}

func hydrateNAT(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.NatGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	n := out.NatGateways[0]
	cfg := map[string]any{
		"subnet_id":         aws.ToString(n.SubnetId),
		"connectivity_type": string(n.ConnectivityType),
	}
	// allocation_id is Optional but NOT Computed -- a multi-EIP NAT gateway
	// has several NatGatewayAddresses entries, and picking the wrong one
	// (not just omitting it) would put a real but incorrect EIP in config.
	// IsPrimary marks which one the provider itself associates with
	// allocation_id/private_ip; the rest are secondary.
	var secAlloc, secIPs []any
	for _, a := range n.NatGatewayAddresses {
		if aws.ToBool(a.IsPrimary) {
			if v := aws.ToString(a.AllocationId); v != "" {
				cfg["allocation_id"] = v
			}
			if v := aws.ToString(a.PrivateIp); v != "" {
				cfg["private_ip"] = v
			}
			continue
		}
		if v := aws.ToString(a.AllocationId); v != "" {
			secAlloc = append(secAlloc, v)
		}
		if v := aws.ToString(a.PrivateIp); v != "" {
			secIPs = append(secIPs, v)
		}
	}
	// no address was marked primary (single-address gateways sometimes omit
	// the flag) -- fall back to the one address there is.
	if _, ok := cfg["allocation_id"]; !ok && len(n.NatGatewayAddresses) == 1 {
		a := n.NatGatewayAddresses[0]
		if v := aws.ToString(a.AllocationId); v != "" {
			cfg["allocation_id"] = v
		}
		if v := aws.ToString(a.PrivateIp); v != "" {
			cfg["private_ip"] = v
		}
	}
	if len(secAlloc) > 0 {
		cfg["secondary_allocation_ids"] = secAlloc
	}
	if len(secIPs) > 0 {
		cfg["secondary_private_ip_addresses"] = secIPs
	}
	return cfg, nil
}

func hydrateEIP(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_eip")
	if err != nil {
		return nil, err
	}
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
		AllocationIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Addresses) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return Generic(out.Addresses[0], sch, nil)
}

// Route tables carry a nested `route` block per non-local route.
func hydrateRouteTable(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.RouteTables) == 0 {
		return nil, fmt.Errorf("not found")
	}
	rt := out.RouteTables[0]
	cfg := map[string]any{"vpc_id": aws.ToString(rt.VpcId)}

	var routes []any
	for _, rte := range rt.Routes {
		if string(rte.Origin) == "CreateRouteTable" {
			continue // the implicit local route
		}
		if gw := aws.ToString(rte.GatewayId); len(gw) > 5 && gw[:5] == "vpce-" {
			// AWS auto-adds this route the moment a gateway VPC endpoint
			// attaches to the table (via the endpoint's own
			// route_table_ids) -- it isn't something the route table
			// itself owns. Emitting it here as well would create a
			// same-config dependency cycle (route table -> endpoint via
			// this route, endpoint -> route table via route_table_ids)
			// with no way to break it on either side; the provider's own
			// docs say this attribute is exported read-only and must not
			// be set in config for exactly this reason.
			continue
		}
		route := map[string]any{}
		if v := aws.ToString(rte.DestinationCidrBlock); v != "" {
			route["cidr_block"] = v
		}
		if v := aws.ToString(rte.DestinationIpv6CidrBlock); v != "" {
			route["ipv6_cidr_block"] = v
		}
		if gw := aws.ToString(rte.GatewayId); gw != "" {
			route["gateway_id"] = gw
		}
		for k, v := range map[string]string{
			"nat_gateway_id":             aws.ToString(rte.NatGatewayId),
			"network_interface_id":       aws.ToString(rte.NetworkInterfaceId),
			"transit_gateway_id":         aws.ToString(rte.TransitGatewayId),
			"vpc_peering_connection_id":  aws.ToString(rte.VpcPeeringConnectionId),
			"destination_prefix_list_id": aws.ToString(rte.DestinationPrefixListId),
			"egress_only_gateway_id":     aws.ToString(rte.EgressOnlyInternetGatewayId),
			"carrier_gateway_id":         aws.ToString(rte.CarrierGatewayId),
			"local_gateway_id":           aws.ToString(rte.LocalGatewayId),
			"core_network_arn":           aws.ToString(rte.CoreNetworkArn),
		} {
			if v != "" {
				route[k] = v
			}
		}
		if len(route) > 1 {
			routes = append(routes, route)
		}
	}
	if len(routes) > 0 {
		cfg["route"] = routes
	}
	return cfg, nil
}

func hydrateTGW(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{TransitGatewayIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.TransitGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	t := out.TransitGateways[0]
	cfg := map[string]any{}
	if v := aws.ToString(t.Description); v != "" {
		cfg["description"] = v
	}
	if o := t.Options; o != nil {
		if o.AmazonSideAsn != nil {
			cfg["amazon_side_asn"] = *o.AmazonSideAsn
		}
		cfg["auto_accept_shared_attachments"] = string(o.AutoAcceptSharedAttachments)
		cfg["default_route_table_association"] = string(o.DefaultRouteTableAssociation)
		cfg["default_route_table_propagation"] = string(o.DefaultRouteTablePropagation)
		cfg["dns_support"] = string(o.DnsSupport)
		cfg["vpn_ecmp_support"] = string(o.VpnEcmpSupport)
		if v := string(o.MulticastSupport); v != "" {
			cfg["multicast_support"] = v
		}
		if v := string(o.SecurityGroupReferencingSupport); v != "" {
			cfg["security_group_referencing_support"] = v
		}
		if len(o.TransitGatewayCidrBlocks) > 0 {
			cfg["transit_gateway_cidr_blocks"] = toAny(o.TransitGatewayCidrBlocks)
		}
	}
	return cfg, nil
}

// hydrateTGWAttach dispatches on ResourceType first: aws_ec2_transit_gateway_vpc_attachment
// and aws_ec2_transit_gateway_peering_attachment share the exact same ARN
// resource segment ("transit-gateway-attachment"), so a peering attachment
// arrives pre-typed as the VPC variant by ResolveTFType's ARN-only
// classification. DescribeTransitGatewayVpcAttachments returns zero results
// for a peering attachment's ID, so the ResourceType check has to happen
// before dispatching, not after a failed VPC-specific lookup.
func hydrateTGWAttach(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := ec2.NewFromConfig(c.Cfg(r.Region))
	generic, gerr := cl.DescribeTransitGatewayAttachments(ctx, &ec2.DescribeTransitGatewayAttachmentsInput{
		TransitGatewayAttachmentIds: []string{r.ID},
	})
	if gerr == nil && len(generic.TransitGatewayAttachments) > 0 &&
		generic.TransitGatewayAttachments[0].ResourceType == ec2types.TransitGatewayAttachmentResourceTypePeering {
		return hydrateTGWPeeringAttach(ctx, c, r)
	}

	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		TransitGatewayAttachmentIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.TransitGatewayVpcAttachments) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.TransitGatewayVpcAttachments[0]
	cfg := map[string]any{
		"transit_gateway_id": aws.ToString(a.TransitGatewayId),
		"vpc_id":             aws.ToString(a.VpcId),
	}
	if len(a.SubnetIds) > 0 {
		cfg["subnet_ids"] = toAny(a.SubnetIds)
	}
	if a.Options != nil {
		cfg["dns_support"] = string(a.Options.DnsSupport)
		cfg["ipv6_support"] = string(a.Options.Ipv6Support)
		if v := string(a.Options.ApplianceModeSupport); v != "" {
			cfg["appliance_mode_support"] = v
		}
		if v := string(a.Options.SecurityGroupReferencingSupport); v != "" {
			cfg["security_group_referencing_support"] = v
		}
	}
	return cfg, nil
}

// hydrateTGWPeeringAttach retypes to aws_ec2_transit_gateway_peering_attachment.
// RequesterTgwInfo is this attachment's own side (transit_gateway_id);
// AccepterTgwInfo is the peer's (peer_transit_gateway_id/peer_account_id/
// peer_region).
func hydrateTGWPeeringAttach(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTransitGatewayPeeringAttachments(ctx, &ec2.DescribeTransitGatewayPeeringAttachmentsInput{
		TransitGatewayAttachmentIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.TransitGatewayPeeringAttachments) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.TransitGatewayPeeringAttachments[0]
	cfg := map[string]any{retypeSentinel: "aws_ec2_transit_gateway_peering_attachment"}
	if a.RequesterTgwInfo != nil {
		cfg["transit_gateway_id"] = aws.ToString(a.RequesterTgwInfo.TransitGatewayId)
	}
	if a.AccepterTgwInfo != nil {
		cfg["peer_transit_gateway_id"] = aws.ToString(a.AccepterTgwInfo.TransitGatewayId)
		cfg["peer_account_id"] = aws.ToString(a.AccepterTgwInfo.OwnerId)
		cfg["peer_region"] = aws.ToString(a.AccepterTgwInfo.Region)
	}
	if a.Options != nil {
		if v := string(a.Options.DynamicRouting); v != "" {
			cfg["options"] = []any{map[string]any{"dynamic_routing": v}}
		}
	}
	return cfg, nil
}

func hydrateVPNGateway(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{VpnGatewayIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.VpnGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.VpnGateways[0]
	cfg := map[string]any{}
	if g.AmazonSideAsn != nil {
		cfg["amazon_side_asn"] = *g.AmazonSideAsn
	}
	if v := aws.ToString(g.AvailabilityZone); v != "" {
		cfg["availability_zone"] = v
	}
	for _, a := range g.VpcAttachments {
		if string(a.State) == "attached" {
			cfg["vpc_id"] = aws.ToString(a.VpcId)
		}
	}
	return cfg, nil
}

func hydrateCustomerGateway(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeCustomerGateways(ctx, &ec2.DescribeCustomerGatewaysInput{CustomerGatewayIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.CustomerGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.CustomerGateways[0]
	cfg := map[string]any{
		"type":       aws.ToString(g.Type),
		"ip_address": aws.ToString(g.IpAddress),
	}
	if v := aws.ToString(g.BgpAsn); v != "" {
		cfg["bgp_asn"] = v
	}
	if v := aws.ToString(g.BgpAsnExtended); v != "" {
		cfg["bgp_asn_extended"] = v
	}
	if v := aws.ToString(g.CertificateArn); v != "" {
		cfg["certificate_arn"] = v
	}
	if v := aws.ToString(g.DeviceName); v != "" {
		cfg["device_name"] = v
	}
	return cfg, nil
}

func hydrateVPNConnection(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{VpnConnectionIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.VpnConnections) == 0 {
		return nil, fmt.Errorf("not found")
	}
	v := out.VpnConnections[0]
	cfg := map[string]any{
		"type":                string(v.Type),
		"customer_gateway_id": aws.ToString(v.CustomerGatewayId),
	}
	if id := aws.ToString(v.TransitGatewayId); id != "" {
		cfg["transit_gateway_id"] = id
	}
	if id := aws.ToString(v.VpnGatewayId); id != "" {
		cfg["vpn_gateway_id"] = id
	}
	if tuns := vpnTunnelConfig(aws.ToString(v.CustomerGatewayConfiguration), v.Options); tuns != nil {
		for k, val := range tuns {
			cfg[k] = val
		}
	}
	if o := v.Options; o != nil {
		if o.StaticRoutesOnly != nil {
			cfg["static_routes_only"] = *o.StaticRoutesOnly
		}
		if o.EnableAcceleration != nil {
			cfg["enable_acceleration"] = *o.EnableAcceleration
		}
		if v := aws.ToString(o.LocalIpv4NetworkCidr); v != "" {
			cfg["local_ipv4_network_cidr"] = v
		}
		if v := aws.ToString(o.LocalIpv6NetworkCidr); v != "" {
			cfg["local_ipv6_network_cidr"] = v
		}
		if v := aws.ToString(o.RemoteIpv4NetworkCidr); v != "" {
			cfg["remote_ipv4_network_cidr"] = v
		}
		if v := aws.ToString(o.RemoteIpv6NetworkCidr); v != "" {
			cfg["remote_ipv6_network_cidr"] = v
		}
		if v := aws.ToString(o.OutsideIpAddressType); v != "" {
			cfg["outside_ip_address_type"] = v
		}
		if v := string(o.TunnelInsideIpVersion); v != "" {
			cfg["tunnel_inside_ip_version"] = v
		}
		if v := string(o.TunnelBandwidth); v != "" {
			cfg["tunnel_bandwidth"] = v
		}
		if v := aws.ToString(o.TransportTransitGatewayAttachmentId); v != "" {
			cfg["transport_transit_gateway_attachment_id"] = v
		}
	}
	return cfg, nil
}

// xmlVpnConnectionConfig is CustomerGatewayConfiguration, an XML document
// (a completely separate response field from the JSON Options.TunnelOptions
// used above) -- the provider's own Read parses this same XML for the one
// handful of fields it doesn't get from TunnelOptions at all (address,
// bgp_asn, bgp_holdtime, cgw/vgw_inside_address, preshared_key). Field names
// and XML tags copied verbatim from the provider's own
// customerGatewayConfigurationToTunnelInfo/xmlIpsecTunnel.
type xmlVpnConnectionConfig struct {
	Tunnels []xmlIpsecTunnel `xml:"ipsec_tunnel"`
}

type xmlIpsecTunnel struct {
	BGPASN           string `xml:"vpn_gateway>bgp>asn"`
	BGPHoldTime      int32  `xml:"vpn_gateway>bgp>hold_time"`
	CgwInsideAddress string `xml:"customer_gateway>tunnel_inside_address>ip_address"`
	OutsideAddress   string `xml:"vpn_gateway>tunnel_outside_address>ip_address"`
	PreSharedKey     string `xml:"ike>pre_shared_key"`
	VgwInsideAddress string `xml:"vpn_gateway>tunnel_inside_address>ip_address"`
}

// vpnTunnelConfig builds tunnel1_*/tunnel2_* from both of DescribeVpnConnections'
// two, independently-shaped tunnel data sources: the XML CustomerGatewayConfiguration
// document (unordered) and the JSON Options.TunnelOptions list (also unordered,
// and not necessarily in the same order as the XML tunnels). Nil (no tunnel1_*/
// tunnel2_* attributes at all) if there aren't exactly two of each -- a
// same-shape mismatch means something about this connection doesn't match the
// standard two-tunnel model this whole scheme assumes, and guessing further
// risks mislabeling which tunnel is which rather than just omitting the block.
//
// Tunnel1-vs-tunnel2 assignment: the provider's own Read reorders the XML
// tunnels to match hints from the resource's OWN CURRENT config
// (tunnel1_preshared_key / tunnel1_inside_cidr / tunnel1_inside_ipv6_cidr) when
// present, falling back to a lexicographic sort by outside (tunnel) address
// otherwise. On a fresh import there IS no current config yet (d.Get returns
// each hint's zero value pre-import), so the hint-matching branches never
// fire in practice here -- only the address-sort fallback ever applies, and
// that's the only ordering this replicates.
func vpnTunnelConfig(xmlConfig string, opts *ec2types.VpnConnectionOptions) map[string]any {
	if xmlConfig == "" || opts == nil || len(opts.TunnelOptions) != 2 {
		return nil
	}
	var doc xmlVpnConnectionConfig
	if err := xml.Unmarshal([]byte(xmlConfig), &doc); err != nil || len(doc.Tunnels) != 2 {
		return nil
	}
	tunnels := doc.Tunnels
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].OutsideAddress < tunnels[j].OutsideAddress })

	// match each JSON TunnelOption to its XML counterpart by outside
	// address -- the one fact both data sources independently agree on.
	byAddr := map[string]ec2types.TunnelOption{}
	for _, to := range opts.TunnelOptions {
		byAddr[aws.ToString(to.OutsideIpAddress)] = to
	}

	cfg := map[string]any{}
	for i, xt := range tunnels {
		n := i + 1 // tunnel1, tunnel2
		to, ok := byAddr[xt.OutsideAddress]
		if !ok {
			return nil // can't reliably attribute this tunnel's JSON-side config
		}
		p := fmt.Sprintf("tunnel%d_", n)
		// address/bgp_asn/bgp_holdtime/cgw_inside_address/vgw_inside_address
		// are Computed-only in the schema -- the XML is only needed here to
		// determine tunnel1-vs-tunnel2 order and to correlate the JSON side
		// by address; preshared_key is the one XML field that's actually
		// settable.
		if xt.PreSharedKey != "" {
			cfg[p+"preshared_key"] = xt.PreSharedKey
		}
		if v := aws.ToString(to.DpdTimeoutAction); v != "" {
			cfg[p+"dpd_timeout_action"] = v
		}
		if to.DpdTimeoutSeconds != nil {
			cfg[p+"dpd_timeout_seconds"] = *to.DpdTimeoutSeconds
		}
		if to.EnableTunnelLifecycleControl != nil {
			cfg[p+"enable_tunnel_lifecycle_control"] = *to.EnableTunnelLifecycleControl
		}
		if v := aws.ToString(to.TunnelInsideCidr); v != "" {
			cfg[p+"inside_cidr"] = v
		}
		if v := aws.ToString(to.TunnelInsideIpv6Cidr); v != "" {
			cfg[p+"inside_ipv6_cidr"] = v
		}
		if v := aws.ToString(to.StartupAction); v != "" {
			cfg[p+"startup_action"] = v
		}
		if to.ReplayWindowSize != nil {
			cfg[p+"replay_window_size"] = *to.ReplayWindowSize
		}
		if to.RekeyMarginTimeSeconds != nil {
			cfg[p+"rekey_margin_time_seconds"] = *to.RekeyMarginTimeSeconds
		}
		if to.RekeyFuzzPercentage != nil {
			cfg[p+"rekey_fuzz_percentage"] = *to.RekeyFuzzPercentage
		}
		if to.Phase1LifetimeSeconds != nil {
			cfg[p+"phase1_lifetime_seconds"] = *to.Phase1LifetimeSeconds
		}
		if to.Phase2LifetimeSeconds != nil {
			cfg[p+"phase2_lifetime_seconds"] = *to.Phase2LifetimeSeconds
		}
		if v := ikeVersions(to.IkeVersions); len(v) > 0 {
			cfg[p+"ike_versions"] = v
		}
		if v := dhGroups(to.Phase1DHGroupNumbers); len(v) > 0 {
			cfg[p+"phase1_dh_group_numbers"] = v
		}
		if v := dhGroups2(to.Phase2DHGroupNumbers); len(v) > 0 {
			cfg[p+"phase2_dh_group_numbers"] = v
		}
		if v := encAlgos1(to.Phase1EncryptionAlgorithms); len(v) > 0 {
			cfg[p+"phase1_encryption_algorithms"] = v
		}
		if v := encAlgos2(to.Phase2EncryptionAlgorithms); len(v) > 0 {
			cfg[p+"phase2_encryption_algorithms"] = v
		}
		if v := intAlgos1(to.Phase1IntegrityAlgorithms); len(v) > 0 {
			cfg[p+"phase1_integrity_algorithms"] = v
		}
		if v := intAlgos2(to.Phase2IntegrityAlgorithms); len(v) > 0 {
			cfg[p+"phase2_integrity_algorithms"] = v
		}
	}
	return cfg
}

func ikeVersions(vs []ec2types.IKEVersionsListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToString(v.Value))
	}
	return out
}

func dhGroups(vs []ec2types.Phase1DHGroupNumbersListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToInt32(v.Value))
	}
	return out
}

func dhGroups2(vs []ec2types.Phase2DHGroupNumbersListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToInt32(v.Value))
	}
	return out
}

func encAlgos1(vs []ec2types.Phase1EncryptionAlgorithmsListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToString(v.Value))
	}
	return out
}

func encAlgos2(vs []ec2types.Phase2EncryptionAlgorithmsListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToString(v.Value))
	}
	return out
}

func intAlgos1(vs []ec2types.Phase1IntegrityAlgorithmsListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToString(v.Value))
	}
	return out
}

func intAlgos2(vs []ec2types.Phase2IntegrityAlgorithmsListValue) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, aws.ToString(v.Value))
	}
	return out
}

// hydrateVPCEndpoint: the SDK's PolicyDocument field doesn't snake-case to
// the schema's "policy" attribute name (the provider renamed it on the
// Terraform side).
func hydrateVPCEndpoint(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_vpc_endpoint")
	if err != nil {
		return nil, err
	}
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.VpcEndpoints) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return Generic(out.VpcEndpoints[0], sch, map[string]string{"policy_document": "policy"})
}

func dhcpOptionsConfig(opts []ec2types.DhcpConfiguration) map[string]any {
	cfg := map[string]any{}
	single := map[string]bool{"domain_name": true, "netbios_node_type": true, "ipv6_address_preferred_lease_time": true}
	for _, o := range opts {
		attr, ok := dhcpOptionKeys[aws.ToString(o.Key)]
		if !ok {
			continue
		}
		var vals []string
		for _, v := range o.Values {
			if s := aws.ToString(v.Value); s != "" {
				vals = append(vals, s)
			}
		}
		if len(vals) == 0 {
			continue
		}
		if single[attr] {
			cfg[attr] = vals[0]
		} else {
			cfg[attr] = toAny(vals)
		}
	}
	return cfg
}

func hydrateDHCPOptions(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.DhcpOptions) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return dhcpOptionsConfig(out.DhcpOptions[0].DhcpConfigurations), nil
}

func hydrateNetworkACL(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{NetworkAclIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.NetworkAcls) == 0 {
		return nil, fmt.Errorf("not found")
	}
	acl := out.NetworkAcls[0]
	cfg := map[string]any{}
	if aws.ToBool(acl.IsDefault) {
		// the provider flatly refuses to import a VPC's default network ACL
		// as aws_network_acl ("use the aws_default_network_acl resource
		// instead"). Same rule shape, different identifying attribute
		// (default_network_acl_id, not vpc_id -- vpc_id is computed-only
		// on this type).
		cfg[retypeSentinel] = "aws_default_network_acl"
		cfg["default_network_acl_id"] = r.ID
	} else {
		cfg["vpc_id"] = aws.ToString(acl.VpcId)
	}
	var subnets []any
	for _, a := range acl.Associations {
		subnets = append(subnets, aws.ToString(a.SubnetId))
	}
	if len(subnets) > 0 {
		cfg["subnet_ids"] = subnets
	}
	mkRules := func(egress bool) []any {
		var rules []any
		for _, e := range acl.Entries {
			if aws.ToBool(e.Egress) != egress || aws.ToInt32(e.RuleNumber) == 32767 {
				continue // 32767 is the implicit deny
			}
			rule := map[string]any{
				"rule_no":  aws.ToInt32(e.RuleNumber),
				"action":   string(e.RuleAction),
				"protocol": aws.ToString(e.Protocol),
				// from_port/to_port/icmp_type/icmp_code are all Required within
				// the ingress/egress object type (the schema doesn't mark them
				// optional the way a plain top-level argument would be) -- AWS
				// only returns PortRange/IcmpTypeCode when the protocol uses
				// them, but the object literal still needs every key present,
				// so the AWS/Terraform convention is 0 for "not applicable"
				// rather than omitting the key.
				"from_port": int32(0),
				"to_port":   int32(0),
				"icmp_type": int32(0),
				"icmp_code": int32(0),
			}
			if v := aws.ToString(e.CidrBlock); v != "" {
				rule["cidr_block"] = v
			}
			if v := aws.ToString(e.Ipv6CidrBlock); v != "" {
				rule["ipv6_cidr_block"] = v
			}
			if e.PortRange != nil {
				rule["from_port"] = aws.ToInt32(e.PortRange.From)
				rule["to_port"] = aws.ToInt32(e.PortRange.To)
			}
			if e.IcmpTypeCode != nil {
				rule["icmp_type"] = aws.ToInt32(e.IcmpTypeCode.Type)
				rule["icmp_code"] = aws.ToInt32(e.IcmpTypeCode.Code)
			}
			rules = append(rules, rule)
		}
		return rules
	}
	if in := mkRules(false); len(in) > 0 {
		cfg["ingress"] = in
	}
	if eg := mkRules(true); len(eg) > 0 {
		cfg["egress"] = eg
	}
	return cfg, nil
}

func fetchNetworkInsightsPath(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeNetworkInsightsPaths(ctx, &ec2.DescribeNetworkInsightsPathsInput{
		NetworkInsightsPathIds: []string{r.ID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.NetworkInsightsPaths) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return out.NetworkInsightsPaths[0], nil
}

func hydrateKeyPair(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	// public_key is Required, but DescribeKeyPairs only returns it when
	// asked -- without IncludePublicKey, this came back empty (invalid
	// config, "public_key is required") for every AWS-generated key pair;
	// only imported ones happened to still work, since AWS always retains
	// an imported key's public material regardless of this flag.
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{
		KeyPairIds:       []string{id},
		IncludePublicKey: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if len(out.KeyPairs) == 0 {
		return nil, fmt.Errorf("not found")
	}
	k := out.KeyPairs[0]
	cfg := map[string]any{"key_name": aws.ToString(k.KeyName)}
	if v := aws.ToString(k.PublicKey); v != "" {
		cfg["public_key"] = v
	}
	return cfg, nil
}

func hydrateEBSVolume(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.Volumes) == 0 {
		return nil, fmt.Errorf("not found")
	}
	v := out.Volumes[0]
	cfg := map[string]any{
		"availability_zone": aws.ToString(v.AvailabilityZone),
		"type":              string(v.VolumeType),
	}
	if v.Size != nil {
		cfg["size"] = *v.Size
	}
	if v.Iops != nil {
		cfg["iops"] = *v.Iops
	}
	if v.Throughput != nil {
		cfg["throughput"] = *v.Throughput
	}
	if v.Encrypted != nil {
		cfg["encrypted"] = *v.Encrypted
	}
	if k := aws.ToString(v.KmsKeyId); k != "" {
		cfg["kms_key_id"] = k
	}
	if aws.ToBool(v.MultiAttachEnabled) {
		cfg["multi_attach_enabled"] = true
	}
	if s := aws.ToString(v.SnapshotId); s != "" {
		cfg["snapshot_id"] = s
	}
	if o := aws.ToString(v.OutpostArn); o != "" {
		cfg["outpost_arn"] = o
	}
	if v.VolumeInitializationRate != nil {
		cfg["volume_initialization_rate"] = *v.VolumeInitializationRate
	}
	return cfg, nil
}

func hydrateFlowLog(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{FlowLogIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.FlowLogs) == 0 {
		return nil, fmt.Errorf("not found")
	}
	f := out.FlowLogs[0]
	cfg := map[string]any{
		"traffic_type": string(f.TrafficType),
	}
	if v := aws.ToString(f.ResourceId); v != "" {
		switch {
		case len(v) > 4 && v[:4] == "vpc-":
			cfg["vpc_id"] = v
		case len(v) > 7 && v[:7] == "subnet-":
			cfg["subnet_id"] = v
		case len(v) > 4 && v[:4] == "eni-":
			cfg["eni_id"] = v
		}
	}
	if v := string(f.LogDestinationType); v != "" {
		cfg["log_destination_type"] = v
	}
	if v := aws.ToString(f.LogDestination); v != "" {
		cfg["log_destination"] = v
	}
	if v := aws.ToString(f.LogGroupName); v != "" {
		cfg["log_group_name"] = v
	}
	if v := aws.ToString(f.DeliverLogsPermissionArn); v != "" {
		cfg["iam_role_arn"] = v
	}
	if v := aws.ToString(f.LogFormat); v != "" {
		cfg["log_format"] = v
	}
	if f.MaxAggregationInterval != nil {
		cfg["max_aggregation_interval"] = *f.MaxAggregationInterval
	}
	return cfg, nil
}

func hydrateManagedPrefixList(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	cl := ec2.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeManagedPrefixLists(ctx, &ec2.DescribeManagedPrefixListsInput{PrefixListIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.PrefixLists) == 0 {
		return nil, fmt.Errorf("not found")
	}
	pl := out.PrefixLists[0]
	if aws.ToString(pl.OwnerId) == "AWS" {
		return nil, fmt.Errorf("AWS-managed prefix list")
	}
	cfg := map[string]any{
		"name":           aws.ToString(pl.PrefixListName),
		"address_family": aws.ToString(pl.AddressFamily),
		"max_entries":    aws.ToInt32(pl.MaxEntries),
	}
	ent, err := cl.GetManagedPrefixListEntries(ctx, &ec2.GetManagedPrefixListEntriesInput{PrefixListId: &id})
	if err == nil {
		var entries []any
		for _, e := range ent.Entries {
			m := map[string]any{"cidr": aws.ToString(e.Cidr)}
			if v := aws.ToString(e.Description); v != "" {
				m["description"] = v
			}
			entries = append(entries, m)
		}
		if len(entries) > 0 {
			cfg["entry"] = entries
		}
	}
	return cfg, nil
}

func hydrateVPCPeering(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{
		VpcPeeringConnectionIds: []string{id},
	})
	if err != nil {
		return nil, err
	}
	if len(out.VpcPeeringConnections) == 0 {
		return nil, fmt.Errorf("not found")
	}
	p := out.VpcPeeringConnections[0]
	cfg := map[string]any{}
	if p.RequesterVpcInfo != nil {
		cfg["vpc_id"] = aws.ToString(p.RequesterVpcInfo.VpcId)
		// the most commonly customized peering setting (cross-VPC private
		// DNS resolution) is nested under {Requester,Accepter}VpcInfo, not a
		// top-level attribute.
		if po := p.RequesterVpcInfo.PeeringOptions; po != nil {
			cfg["requester"] = map[string]any{"allow_remote_vpc_dns_resolution": aws.ToBool(po.AllowDnsResolutionFromRemoteVpc)}
		}
	}
	if p.AccepterVpcInfo != nil {
		cfg["peer_vpc_id"] = aws.ToString(p.AccepterVpcInfo.VpcId)
		cfg["peer_owner_id"] = aws.ToString(p.AccepterVpcInfo.OwnerId)
		cfg["peer_region"] = aws.ToString(p.AccepterVpcInfo.Region)
		if po := p.AccepterVpcInfo.PeeringOptions; po != nil {
			cfg["accepter"] = map[string]any{"allow_remote_vpc_dns_resolution": aws.ToBool(po.AllowDnsResolutionFromRemoteVpc)}
		}
	}
	return cfg, nil
}

func hydrateTGWRouteTable(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeTransitGatewayRouteTables(ctx, &ec2.DescribeTransitGatewayRouteTablesInput{
		TransitGatewayRouteTableIds: []string{id},
	})
	if err != nil {
		return nil, err
	}
	if len(out.TransitGatewayRouteTables) == 0 {
		return nil, fmt.Errorf("not found")
	}
	t := out.TransitGatewayRouteTables[0]
	return map[string]any{"transit_gateway_id": aws.ToString(t.TransitGatewayId)}, nil
}

func hydrateNetworkInterface(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{id},
	})
	if err != nil {
		return nil, err
	}
	if len(out.NetworkInterfaces) == 0 {
		return nil, fmt.Errorf("not found")
	}
	ni := out.NetworkInterfaces[0]
	// Interfaces AWS creates for a managed service (their InterfaceType is not
	// "interface", or they have a requester-managed flag) are not user-managed.
	if string(ni.InterfaceType) != "" && string(ni.InterfaceType) != "interface" {
		return nil, fmt.Errorf("service-managed interface (%s)", ni.InterfaceType)
	}
	if aws.ToBool(ni.RequesterManaged) {
		return nil, fmt.Errorf("requester-managed interface")
	}
	cfg := map[string]any{"subnet_id": aws.ToString(ni.SubnetId)}
	if v := aws.ToString(ni.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(ni.PrivateIpAddress); v != "" {
		cfg["private_ip"] = v
	}
	var privates []any
	for _, p := range ni.PrivateIpAddresses {
		privates = append(privates, aws.ToString(p.PrivateIpAddress))
	}
	if len(privates) > 0 {
		cfg["private_ips"] = privates
	}
	var ipv6 []any
	for _, a := range ni.Ipv6Addresses {
		ipv6 = append(ipv6, aws.ToString(a.Ipv6Address))
	}
	if len(ipv6) > 0 {
		cfg["ipv6_addresses"] = ipv6
	}
	var sgs []any
	for _, g := range ni.Groups {
		sgs = append(sgs, aws.ToString(g.GroupId))
	}
	if len(sgs) > 0 {
		cfg["security_groups"] = sgs
	}
	if ni.SourceDestCheck != nil {
		cfg["source_dest_check"] = *ni.SourceDestCheck
	}
	// only a real instance attachment is a settable argument; ELB/NAT-gateway/
	// VPC-endpoint owned interfaces attach through their own owning resource,
	// not this one, and never carry an InstanceId here.
	if at := ni.Attachment; at != nil && aws.ToString(at.InstanceId) != "" {
		cfg["attachment"] = []any{map[string]any{
			"instance":     aws.ToString(at.InstanceId),
			"device_index": aws.ToInt32(at.DeviceIndex),
		}}
	}
	return cfg, nil
}

func hydrateDXConnection(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := directconnect.NewFromConfig(c.Cfg(r.Region)).DescribeConnections(ctx, &directconnect.DescribeConnectionsInput{ConnectionId: &id})
	if err != nil {
		return nil, err
	}
	if len(out.Connections) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cn := out.Connections[0]
	cfg := map[string]any{
		"name":      aws.ToString(cn.ConnectionName),
		"bandwidth": aws.ToString(cn.Bandwidth),
		"location":  aws.ToString(cn.Location),
	}
	if v := aws.ToString(cn.ProviderName); v != "" {
		cfg["provider_name"] = v
	}
	return cfg, nil
}

func hydrateDXGateway(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := directconnect.NewFromConfig(c.Cfg(r.Region)).DescribeDirectConnectGateways(ctx, &directconnect.DescribeDirectConnectGatewaysInput{
		DirectConnectGatewayId: &id,
	})
	if err != nil {
		return nil, err
	}
	if len(out.DirectConnectGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.DirectConnectGateways[0]
	cfg := map[string]any{"name": aws.ToString(g.DirectConnectGatewayName)}
	if g.AmazonSideAsn != nil {
		cfg["amazon_side_asn"] = fmt.Sprintf("%d", *g.AmazonSideAsn)
	}
	return cfg, nil
}

func hydrateNetworkFirewall(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := networkfirewall.NewFromConfig(c.Cfg(r.Region)).DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{FirewallArn: &arn})
	if err != nil {
		return nil, err
	}
	f := out.Firewall
	if f == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"name":                aws.ToString(f.FirewallName),
		"firewall_policy_arn": aws.ToString(f.FirewallPolicyArn),
		"vpc_id":              aws.ToString(f.VpcId),
	}
	if v := aws.ToString(f.Description); v != "" {
		cfg["description"] = v
	}
	var subs []any
	for _, s := range f.SubnetMappings {
		m := map[string]any{"subnet_id": aws.ToString(s.SubnetId)}
		if v := string(s.IPAddressType); v != "" {
			m["ip_address_type"] = v
		}
		subs = append(subs, m)
	}
	if len(subs) > 0 {
		cfg["subnet_mapping"] = subs
	}
	if f.DeleteProtection {
		cfg["delete_protection"] = true
	}
	if f.FirewallPolicyChangeProtection {
		cfg["firewall_policy_change_protection"] = true
	}
	if f.SubnetChangeProtection {
		cfg["subnet_change_protection"] = true
	}
	if ec := f.EncryptionConfiguration; ec != nil {
		m := map[string]any{"type": string(ec.Type)}
		if v := aws.ToString(ec.KeyId); v != "" {
			m["key_id"] = v
		}
		cfg["encryption_configuration"] = m
	}
	return cfg, nil
}

// dhcpOptionConfig maps DescribeDhcpOptions' key-value list shape
// (DhcpConfigurations: [{Key: "domain-name", Values: [{Value: "x"}]}, ...])
// onto the schema's flat attribute names. Generic() can't do this on its
// own -- there is no top-level "domain_name" key in the API response at
// all, just an opaque list of key/value pairs.
var dhcpOptionKeys = map[string]string{
	"domain-name":                       "domain_name",
	"domain-name-servers":               "domain_name_servers",
	"ntp-servers":                       "ntp_servers",
	"netbios-name-servers":              "netbios_name_servers",
	"netbios-node-type":                 "netbios_node_type",
	"ipv6-address-preferred-lease-time": "ipv6_address_preferred_lease_time",
}
