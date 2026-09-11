package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_route53_zone", fanoutRoute53Records)
}

func fanoutRoute53Records(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	zoneID := parent.ID
	if i := strings.LastIndexByte(zoneID, '/'); i >= 0 {
		zoneID = zoneID[i+1:]
	}
	out, err := route53.NewFromConfig(c.Cfg("")).ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: &zoneID})
	if err != nil {
		return nil, err
	}
	zoneName := strings.TrimSuffix(parentZoneName(parent), ".")
	var kids []model.Resource
	for _, rs := range out.ResourceRecordSets {
		name := strings.TrimSuffix(aws.ToString(rs.Name), ".")
		typ := string(rs.Type)
		// the apex SOA/NS records are managed by the zone resource itself
		if (typ == "SOA" || typ == "NS") && name == zoneName {
			continue
		}
		cfg := map[string]any{
			"zone_id": zoneID,
			"name":    name,
			"type":    typ,
		}
		// SetIdentifier is what distinguishes sibling records of a routing
		// policy group (weighted/latency/failover/geolocation/geoproximity/
		// cidr all share the same name+type by definition) -- without it in
		// both the emitted config AND this resource's own ID, every sibling
		// in a group collided on exactly the same ID, so only one of them
		// ever made it through.
		setID := aws.ToString(rs.SetIdentifier)
		id := zoneID + "_" + name + "_" + typ
		if setID != "" {
			cfg["set_identifier"] = setID
			id += "_" + setID
		}
		if v := aws.ToString(rs.HealthCheckId); v != "" {
			cfg["health_check_id"] = v
		}
		if rs.MultiValueAnswer != nil {
			cfg["multivalue_answer_routing_policy"] = *rs.MultiValueAnswer
		}
		switch {
		case rs.Weight != nil:
			cfg["weighted_routing_policy"] = []any{map[string]any{"weight": *rs.Weight}}
		case rs.Failover != "":
			cfg["failover_routing_policy"] = []any{map[string]any{"type": string(rs.Failover)}}
		case rs.Region != "":
			cfg["latency_routing_policy"] = []any{map[string]any{"region": string(rs.Region)}}
		case rs.GeoLocation != nil:
			gl := map[string]any{}
			if v := aws.ToString(rs.GeoLocation.ContinentCode); v != "" {
				gl["continent"] = v
			}
			if v := aws.ToString(rs.GeoLocation.CountryCode); v != "" {
				gl["country"] = v
			}
			if v := aws.ToString(rs.GeoLocation.SubdivisionCode); v != "" {
				gl["subdivision"] = v
			}
			cfg["geolocation_routing_policy"] = []any{gl}
		case rs.GeoProximityLocation != nil:
			gp := rs.GeoProximityLocation
			m := map[string]any{}
			if v := aws.ToString(gp.AWSRegion); v != "" {
				m["aws_region"] = v
			}
			if v := aws.ToString(gp.LocalZoneGroup); v != "" {
				m["local_zone_group"] = v
			}
			if gp.Bias != nil {
				m["bias"] = *gp.Bias
			}
			if co := gp.Coordinates; co != nil {
				m["coordinates"] = []any{map[string]any{
					"latitude": aws.ToString(co.Latitude), "longitude": aws.ToString(co.Longitude),
				}}
			}
			cfg["geoproximity_routing_policy"] = []any{m}
		case rs.CidrRoutingConfig != nil:
			cfg["cidr_routing_policy"] = []any{map[string]any{
				"collection_id": aws.ToString(rs.CidrRoutingConfig.CollectionId),
				"location_name": aws.ToString(rs.CidrRoutingConfig.LocationName),
			}}
		}
		if rs.AliasTarget != nil {
			cfg["alias"] = map[string]any{
				"name":                   strings.TrimSuffix(aws.ToString(rs.AliasTarget.DNSName), "."),
				"zone_id":                aws.ToString(rs.AliasTarget.HostedZoneId),
				"evaluate_target_health": rs.AliasTarget.EvaluateTargetHealth,
			}
		} else {
			if rs.TTL != nil {
				cfg["ttl"] = *rs.TTL
			}
			var recs []any
			for _, rr := range rs.ResourceRecords {
				recs = append(recs, aws.ToString(rr.Value))
			}
			if len(recs) > 0 {
				cfg["records"] = recs
			}
		}
		kids = append(kids, model.Resource{
			Service: "route53", Type: "record", TFType: "aws_route53_record",
			Account: parent.Account,
			ID:      id,
			Config:  cfg,
		})
	}

	kids = append(kids, fanoutRoute53DNSSEC(ctx, c, parent, zoneID)...)

	return kids, nil
}

// fanoutRoute53DNSSEC expands a zone into its DNSSEC signing status and any
// key-signing keys -- GetDNSSEC returns both in one call, but the schema
// models them as two separate resource types (and the zone's own signing
// status isn't otherwise readable from ListResourceRecordSets/GetHostedZone
// at all).
func fanoutRoute53DNSSEC(ctx context.Context, c *Clients, parent model.Resource, zoneID string) []model.Resource {
	out, err := route53.NewFromConfig(c.Cfg("")).GetDNSSEC(ctx, &route53.GetDNSSECInput{HostedZoneId: &zoneID})
	if err != nil || out.Status == nil {
		return nil
	}
	var kids []model.Resource
	kids = append(kids, model.Resource{
		Service: "route53", Type: "hosted-zone-dnssec", TFType: "aws_route53_hosted_zone_dnssec",
		Account: parent.Account,
		ID:      zoneID, ImportID: zoneID,
		Config: map[string]any{
			"hosted_zone_id": zoneID,
			"signing_status": aws.ToString(out.Status.ServeSignature),
		},
	})
	for _, ksk := range out.KeySigningKeys {
		name := aws.ToString(ksk.Name)
		if name == "" {
			continue
		}
		id := zoneID + "," + name
		cfg := map[string]any{
			"hosted_zone_id": zoneID,
			"name":           name,
		}
		if v := aws.ToString(ksk.KmsArn); v != "" {
			cfg["key_management_service_arn"] = v
		}
		if v := aws.ToString(ksk.Status); v != "" {
			cfg["status"] = v
		}
		kids = append(kids, model.Resource{
			Service: "route53", Type: "key-signing-key", TFType: "aws_route53_key_signing_key",
			Account: parent.Account,
			ID:      id, ImportID: id,
			Config: cfg,
		})
	}
	return kids
}

func parentZoneName(parent model.Resource) string {
	if parent.Config != nil {
		if n, ok := parent.Config["name"].(string); ok {
			return n
		}
	}
	return ""
}
