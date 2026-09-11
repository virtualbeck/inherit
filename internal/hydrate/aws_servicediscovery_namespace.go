package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	sdtypes "github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_service_discovery_http_namespace", hydrateSDNamespace) }

// hydrateSDNamespace handles all three Cloud Map namespace types
// (private_dns/public_dns/http) through one registration: ListNamespaces
// returns all of them mixed together under the same "namespace" ARN
// resource segment with no way to tell them apart before hydrating, so this
// registers under one placeholder TFType and uses retypeSentinel to
// redirect to the real one once GetNamespace reveals it -- same pattern as
// the VPC default-network-ACL/default-VPC retypes.
func hydrateSDNamespace(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := servicediscovery.NewFromConfig(c.Cfg(r.Region))
	id := r.ID
	out, err := cl.GetNamespace(ctx, &servicediscovery.GetNamespaceInput{Id: &id})
	if err != nil || out.Namespace == nil {
		return nil, err
	}
	ns := out.Namespace
	cfg := map[string]any{"name": aws.ToString(ns.Name)}
	if v := aws.ToString(ns.Description); v != "" {
		cfg["description"] = v
	}

	// hosted_zone (both DNS types) and http_name (HTTP) are Computed-only
	// in the schema -- never written. name/description/tags are the only
	// real settable attributes on public_dns and http; private_dns
	// additionally needs vpc, handled below.
	switch ns.Type {
	case sdtypes.NamespaceTypeDnsPrivate:
		cfg[retypeSentinel] = "aws_service_discovery_private_dns_namespace"
		// vpc has no Read equivalent at all on the Cloud Map side (Create
		// takes it, Read never sets it back) -- but a private DNS
		// namespace's Route53 zone is a real, recoverable cross-service
		// source of truth for exactly this, since GetHostedZone returns
		// the VPCs a private zone is associated with, and
		// CreatePrivateDnsNamespace only ever takes one.
		if ns.Properties != nil && ns.Properties.DnsProperties != nil {
			if zoneID := aws.ToString(ns.Properties.DnsProperties.HostedZoneId); zoneID != "" {
				if hz, herr := route53.NewFromConfig(c.Cfg(r.Region)).GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: &zoneID}); herr == nil && len(hz.VPCs) > 0 {
					if vpcID := aws.ToString(hz.VPCs[0].VPCId); vpcID != "" {
						cfg["vpc"] = vpcID
					}
				}
			}
		}
	case sdtypes.NamespaceTypeDnsPublic:
		cfg[retypeSentinel] = "aws_service_discovery_public_dns_namespace"
	default: // HTTP
		cfg[retypeSentinel] = "aws_service_discovery_http_namespace"
	}

	return cfg, nil
}
