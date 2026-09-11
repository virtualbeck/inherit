package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_dx_private_virtual_interface", hydrateDXVirtualInterface) }

// hydrateDXVirtualInterface dispatches on VirtualInterfaceType: private,
// public, and transit virtual interfaces all share the same ARN resource
// segment ("dxvif", by convention with the already-covered
// aws_dx_connection's "dxcon" -- DescribeTags takes ARNs directly, so a real
// ARN convention exists here even though DescribeVirtualInterfaces' own
// response never echoes one back). Transit isn't a currently-covered
// Terraform type, so that case is left unhandled.
func hydrateDXVirtualInterface(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := directconnect.NewFromConfig(c.Cfg(r.Region)).DescribeVirtualInterfaces(ctx, &directconnect.DescribeVirtualInterfacesInput{VirtualInterfaceId: &id})
	if err != nil {
		return nil, err
	}
	if len(out.VirtualInterfaces) == 0 {
		return nil, fmt.Errorf("not found")
	}
	v := out.VirtualInterfaces[0]

	cfg := map[string]any{
		"connection_id":  aws.ToString(v.ConnectionId),
		"vlan":           v.Vlan,
		"address_family": string(v.AddressFamily),
		"bgp_asn":        v.Asn,
	}
	if name := aws.ToString(v.VirtualInterfaceName); name != "" {
		cfg["name"] = name
	}
	if val := aws.ToString(v.AmazonAddress); val != "" {
		cfg["amazon_address"] = val
	}
	if val := aws.ToString(v.CustomerAddress); val != "" {
		cfg["customer_address"] = val
	}
	if val := aws.ToString(v.AuthKey); val != "" {
		cfg["bgp_auth_key"] = val
	}
	if v.Mtu != nil {
		cfg["mtu"] = *v.Mtu
	}
	if v.SiteLinkEnabled != nil {
		cfg["sitelink_enabled"] = *v.SiteLinkEnabled
	}

	switch aws.ToString(v.VirtualInterfaceType) {
	case "private":
		cfg[retypeSentinel] = "aws_dx_private_virtual_interface"
		if val := aws.ToString(v.DirectConnectGatewayId); val != "" {
			cfg["dx_gateway_id"] = val
		}
		if val := aws.ToString(v.VirtualGatewayId); val != "" {
			cfg["vpn_gateway_id"] = val
		}
	case "public":
		cfg[retypeSentinel] = "aws_dx_public_virtual_interface"
		if len(v.RouteFilterPrefixes) > 0 {
			var prefixes []any
			for _, p := range v.RouteFilterPrefixes {
				if val := aws.ToString(p.Cidr); val != "" {
					prefixes = append(prefixes, val)
				}
			}
			if len(prefixes) > 0 {
				cfg["route_filter_prefixes"] = prefixes
			}
		}
	default:
		return nil, fmt.Errorf("DX virtual interface type %q not supported", aws.ToString(v.VirtualInterfaceType))
	}

	return cfg, nil
}
