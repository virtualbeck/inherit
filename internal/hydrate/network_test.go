package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestDhcpOptionsConfig(t *testing.T) {
	// DescribeDhcpOptions returns an opaque key/value list (AWS's own
	// hyphenated key names), not the schema's flat attribute names -- this
	// is the only thing that translates one into the other.
	opts := []ec2types.DhcpConfiguration{
		{Key: aws.String("domain-name"), Values: []ec2types.AttributeValue{{Value: aws.String("example.com")}}},
		{Key: aws.String("domain-name-servers"), Values: []ec2types.AttributeValue{
			{Value: aws.String("10.0.0.2")}, {Value: aws.String("10.0.0.3")},
		}},
		{Key: aws.String("netbios-node-type"), Values: []ec2types.AttributeValue{{Value: aws.String("2")}}},
		{Key: aws.String("some-future-unknown-option")}, // must not panic or leak through
	}

	cfg := dhcpOptionsConfig(opts)

	if cfg["domain_name"] != "example.com" {
		t.Errorf("domain_name = %v, want example.com", cfg["domain_name"])
	}
	servers, ok := cfg["domain_name_servers"].([]any)
	if !ok || len(servers) != 2 || servers[0] != "10.0.0.2" || servers[1] != "10.0.0.3" {
		t.Errorf("domain_name_servers = %v, want [10.0.0.2 10.0.0.3]", cfg["domain_name_servers"])
	}
	if cfg["netbios_node_type"] != "2" {
		t.Errorf("netbios_node_type = %v, want \"2\"", cfg["netbios_node_type"])
	}
	if _, ok := cfg["some_future_unknown_option"]; ok {
		t.Error("an unrecognized DHCP option key must not appear in the output at all")
	}
}

// realistic shape of what DescribeVpnConnections' CustomerGatewayConfiguration
// actually returns (trimmed to the fields vpnTunnelConfig reads); tunnels
// deliberately listed out of the "tunnel1 < tunnel2" address order, matching
// the real, documented unordered-ness this function has to correct for.
const testVPNCustomerGatewayXML = `<vpn_connection id="vpn-1">
  <ipsec_tunnel>
    <vpn_gateway>
      <tunnel_outside_address><ip_address>203.0.113.2</ip_address></tunnel_outside_address>
      <tunnel_inside_address><ip_address>169.254.1.1</ip_address></tunnel_inside_address>
      <bgp><asn>65000</asn><hold_time>30</hold_time></bgp>
    </vpn_gateway>
    <customer_gateway>
      <tunnel_inside_address><ip_address>169.254.1.2</ip_address></tunnel_inside_address>
    </customer_gateway>
    <ike><pre_shared_key>secondkey</pre_shared_key></ike>
  </ipsec_tunnel>
  <ipsec_tunnel>
    <vpn_gateway>
      <tunnel_outside_address><ip_address>203.0.113.1</ip_address></tunnel_outside_address>
      <tunnel_inside_address><ip_address>169.254.0.1</ip_address></tunnel_inside_address>
      <bgp><asn>65000</asn><hold_time>30</hold_time></bgp>
    </vpn_gateway>
    <customer_gateway>
      <tunnel_inside_address><ip_address>169.254.0.2</ip_address></tunnel_inside_address>
    </customer_gateway>
    <ike><pre_shared_key>firstkey</pre_shared_key></ike>
  </ipsec_tunnel>
</vpn_connection>`

func TestVPNTunnelConfig(t *testing.T) {
	opts := &ec2types.VpnConnectionOptions{
		TunnelOptions: []ec2types.TunnelOption{
			// deliberately listed in the SAME (non-address-sorted) order
			// as the XML above, to prove matching is by address, not index.
			{
				OutsideIpAddress: aws.String("203.0.113.2"),
				DpdTimeoutAction: aws.String("clear"),
				IkeVersions:      []ec2types.IKEVersionsListValue{{Value: aws.String("ikev2")}},
			},
			{
				OutsideIpAddress: aws.String("203.0.113.1"),
				DpdTimeoutAction: aws.String("restart"),
				IkeVersions:      []ec2types.IKEVersionsListValue{{Value: aws.String("ikev1")}},
			},
		},
	}

	cfg := vpnTunnelConfig(testVPNCustomerGatewayXML, opts)
	if cfg == nil {
		t.Fatal("vpnTunnelConfig returned nil")
	}

	// tunnel1 must get the preshared_key from the tunnel with the
	// lexicographically smaller outside address (203.0.113.1 -> "firstkey"),
	// regardless of XML/JSON list order. address/bgp_asn/bgp_holdtime/
	// cgw_inside_address/vgw_inside_address are deliberately NOT asserted
	// here -- all five are Computed-only in the schema and must never
	// appear in generated config at all.
	if cfg["tunnel1_preshared_key"] != "firstkey" {
		t.Errorf("tunnel1_preshared_key = %v, want firstkey", cfg["tunnel1_preshared_key"])
	}
	if cfg["tunnel2_preshared_key"] != "secondkey" {
		t.Errorf("tunnel2_preshared_key = %v, want secondkey", cfg["tunnel2_preshared_key"])
	}
	for _, computedOnly := range []string{
		"tunnel1_address", "tunnel2_address", "tunnel1_bgp_asn", "tunnel2_bgp_asn",
		"tunnel1_bgp_holdtime", "tunnel2_bgp_holdtime",
		"tunnel1_cgw_inside_address", "tunnel2_cgw_inside_address",
		"tunnel1_vgw_inside_address", "tunnel2_vgw_inside_address",
	} {
		if _, ok := cfg[computedOnly]; ok {
			t.Errorf("%s must not appear in generated config (Computed-only in the schema)", computedOnly)
		}
	}
	// JSON-sourced fields matched by outside address, not list position:
	// tunnel1 (203.0.113.1) must get the SECOND TunnelOptions[] entry.
	if cfg["tunnel1_dpd_timeout_action"] != "restart" {
		t.Errorf("tunnel1_dpd_timeout_action = %v, want restart (matched by address, not index)", cfg["tunnel1_dpd_timeout_action"])
	}
	if cfg["tunnel2_dpd_timeout_action"] != "clear" {
		t.Errorf("tunnel2_dpd_timeout_action = %v, want clear", cfg["tunnel2_dpd_timeout_action"])
	}
	ike1, _ := cfg["tunnel1_ike_versions"].([]any)
	if len(ike1) != 1 || ike1[0] != "ikev1" {
		t.Errorf("tunnel1_ike_versions = %v, want [ikev1]", cfg["tunnel1_ike_versions"])
	}
}

func TestVPNTunnelConfigNilCases(t *testing.T) {
	if got := vpnTunnelConfig("", &ec2types.VpnConnectionOptions{TunnelOptions: make([]ec2types.TunnelOption, 2)}); got != nil {
		t.Errorf("empty XML: got %v, want nil", got)
	}
	if got := vpnTunnelConfig(testVPNCustomerGatewayXML, nil); got != nil {
		t.Errorf("nil options: got %v, want nil", got)
	}
	if got := vpnTunnelConfig(testVPNCustomerGatewayXML, &ec2types.VpnConnectionOptions{TunnelOptions: make([]ec2types.TunnelOption, 1)}); got != nil {
		t.Errorf("only 1 TunnelOption: got %v, want nil", got)
	}
	// TunnelOptions' outside addresses don't match anything in the XML at
	// all -- must bail rather than attribute JSON config to the wrong tunnel.
	mismatched := &ec2types.VpnConnectionOptions{TunnelOptions: []ec2types.TunnelOption{
		{OutsideIpAddress: aws.String("198.51.100.1")},
		{OutsideIpAddress: aws.String("198.51.100.2")},
	}}
	if got := vpnTunnelConfig(testVPNCustomerGatewayXML, mismatched); got != nil {
		t.Errorf("no matching outside addresses: got %v, want nil", got)
	}
}
