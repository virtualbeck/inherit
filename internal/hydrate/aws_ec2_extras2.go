package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_ec2_capacity_reservation", hydrateEC2CapacityReservation)
	register("aws_ec2_instance_connect_endpoint", hydrateEC2InstanceConnectEndpoint)
	register("aws_ec2_carrier_gateway", hydrateEC2CarrierGateway)
	register("aws_ec2_host", hydrateEC2Host)
}

func hydrateEC2CapacityReservation(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeCapacityReservations(ctx, &ec2.DescribeCapacityReservationsInput{CapacityReservationIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.CapacityReservations) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cr := out.CapacityReservations[0]
	cfg := map[string]any{
		"availability_zone": aws.ToString(cr.AvailabilityZone),
		"instance_type":     aws.ToString(cr.InstanceType),
		"instance_platform": string(cr.InstancePlatform),
		"instance_count":    int(aws.ToInt32(cr.TotalInstanceCount)),
	}
	if v := string(cr.Tenancy); v != "" {
		cfg["tenancy"] = v
	}
	if v := string(cr.InstanceMatchCriteria); v != "" {
		cfg["instance_match_criteria"] = v
	}
	if v := string(cr.EndDateType); v != "" {
		cfg["end_date_type"] = v
	}
	if cr.EndDate != nil {
		cfg["end_date"] = cr.EndDate.Format("2006-01-02T15:04:05Z07:00")
	}
	if cr.EbsOptimized != nil {
		cfg["ebs_optimized"] = *cr.EbsOptimized
	}
	if cr.EphemeralStorage != nil {
		cfg["ephemeral_storage"] = *cr.EphemeralStorage
	}
	if v := aws.ToString(cr.OutpostArn); v != "" {
		cfg["outpost_arn"] = v
	}
	if v := aws.ToString(cr.PlacementGroupArn); v != "" {
		cfg["placement_group_arn"] = v
	}
	if len(cr.Tags) > 0 {
		cfg["tags"] = ec2TagMap(cr.Tags)
	}
	return cfg, nil
}

func hydrateEC2InstanceConnectEndpoint(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeInstanceConnectEndpoints(ctx, &ec2.DescribeInstanceConnectEndpointsInput{InstanceConnectEndpointIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.InstanceConnectEndpoints) == 0 {
		return nil, fmt.Errorf("not found")
	}
	e := out.InstanceConnectEndpoints[0]
	cfg := map[string]any{
		"subnet_id": aws.ToString(e.SubnetId),
	}
	if v := string(e.IpAddressType); v != "" {
		cfg["ip_address_type"] = v
	}
	if e.PreserveClientIp != nil {
		cfg["preserve_client_ip"] = *e.PreserveClientIp
	}
	if len(e.SecurityGroupIds) > 0 {
		cfg["security_group_ids"] = toAny(e.SecurityGroupIds)
	}
	if len(e.Tags) > 0 {
		cfg["tags"] = ec2TagMap(e.Tags)
	}
	return cfg, nil
}

func hydrateEC2CarrierGateway(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeCarrierGateways(ctx, &ec2.DescribeCarrierGatewaysInput{CarrierGatewayIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.CarrierGateways) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.CarrierGateways[0]
	cfg := map[string]any{"vpc_id": aws.ToString(g.VpcId)}
	if len(g.Tags) > 0 {
		cfg["tags"] = ec2TagMap(g.Tags)
	}
	return cfg, nil
}

func hydrateEC2Host(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeHosts(ctx, &ec2.DescribeHostsInput{HostIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.Hosts) == 0 {
		return nil, fmt.Errorf("not found")
	}
	h := out.Hosts[0]
	cfg := map[string]any{
		"availability_zone": aws.ToString(h.AvailabilityZone),
	}
	if v := string(h.AutoPlacement); v != "" {
		cfg["auto_placement"] = v
	}
	if v := string(h.HostRecovery); v != "" {
		cfg["host_recovery"] = v
	}
	if v := aws.ToString(h.OutpostArn); v != "" {
		cfg["outpost_arn"] = v
	}
	if v := aws.ToString(h.AssetId); v != "" {
		cfg["asset_id"] = v
	}
	if h.HostProperties != nil {
		if v := aws.ToString(h.HostProperties.InstanceType); v != "" {
			cfg["instance_type"] = v
		}
		if v := aws.ToString(h.HostProperties.InstanceFamily); v != "" {
			cfg["instance_family"] = v
		}
	}
	if len(h.Tags) > 0 {
		cfg["tags"] = ec2TagMap(h.Tags)
	}
	return cfg, nil
}
