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

// Namespace types share a segment; retype after Get.
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

	// hosted_zone and http_name are computed-only
	switch ns.Type {
	case sdtypes.NamespaceTypeDnsPrivate:
		cfg[retypeSentinel] = "aws_service_discovery_private_dns_namespace"
		// vpc isn't readable here; recover it from Route53
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
