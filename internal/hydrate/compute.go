package hydrate

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	as "github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_instance", hydrateInstance)
	register("aws_launch_template", hydrateLaunchTemplate)
	register("aws_autoscaling_group", hydrateASG)
	register("aws_batch_compute_environment", hydrateBatchComputeEnv)
	register("aws_batch_job_queue", hydrateBatchJobQueue)
	register("aws_emr_cluster", hydrateEMRCluster)
	register("aws_elastic_beanstalk_application", hydrateEBApplication)
	register("aws_elastic_beanstalk_environment", hydrateEBEnvironment)
}

func hydrateInstance(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("not found")
	}
	i := out.Reservations[0].Instances[0]
	cfg := map[string]any{
		"instance_type": string(i.InstanceType),
		"ami":           aws.ToString(i.ImageId),
	}
	if v := aws.ToString(i.SubnetId); v != "" {
		cfg["subnet_id"] = v
	}
	if v := aws.ToString(i.KeyName); v != "" {
		cfg["key_name"] = v
	}
	if v := aws.ToString(i.PrivateIpAddress); v != "" {
		cfg["private_ip"] = v
	}
	if i.IamInstanceProfile != nil {
		// the provider stores this as the profile name, not the ARN
		arn := aws.ToString(i.IamInstanceProfile.Arn)
		if x := strings.LastIndexByte(arn, '/'); x >= 0 {
			arn = arn[x+1:]
		}
		if arn != "" {
			cfg["iam_instance_profile"] = arn
		}
	}
	var sgs []any
	for _, g := range i.SecurityGroups {
		sgs = append(sgs, aws.ToString(g.GroupId))
	}
	if len(sgs) > 0 {
		cfg["vpc_security_group_ids"] = sgs
	}
	if i.EbsOptimized != nil {
		cfg["ebs_optimized"] = *i.EbsOptimized
	}
	if i.Placement != nil {
		if v := aws.ToString(i.Placement.AvailabilityZone); v != "" {
			cfg["availability_zone"] = v
		}
		if v := string(i.Placement.Tenancy); v != "" && v != "default" {
			cfg["tenancy"] = v
		}
	}
	if i.Monitoring != nil && string(i.Monitoring.State) == "enabled" {
		cfg["monitoring"] = true
	}
	if mo := i.MetadataOptions; mo != nil {
		m := map[string]any{}
		if v := string(mo.HttpEndpoint); v != "" {
			m["http_endpoint"] = v
		}
		if v := string(mo.HttpProtocolIpv6); v != "" {
			m["http_protocol_ipv6"] = v
		}
		if v := string(mo.HttpTokens); v != "" {
			m["http_tokens"] = v
		}
		if mo.HttpPutResponseHopLimit != nil {
			m["http_put_response_hop_limit"] = *mo.HttpPutResponseHopLimit
		}
		if v := string(mo.InstanceMetadataTags); v != "" {
			m["instance_metadata_tags"] = v
		}
		if len(m) > 0 {
			cfg["metadata_options"] = []any{m}
		}
	}
	if co := i.CpuOptions; co != nil {
		m := map[string]any{}
		if co.CoreCount != nil {
			m["core_count"] = *co.CoreCount
		}
		if co.ThreadsPerCore != nil {
			m["threads_per_core"] = *co.ThreadsPerCore
		}
		if v := string(co.AmdSevSnp); v != "" {
			m["amd_sev_snp"] = v
		}
		if v := string(co.NestedVirtualization); v != "" {
			m["nested_virtualization"] = v
		}
		if len(m) > 0 {
			cfg["cpu_options"] = []any{m}
		}
	}
	if eo := i.EnclaveOptions; eo != nil && eo.Enabled != nil {
		cfg["enclave_options"] = []any{map[string]any{"enabled": *eo.Enabled}}
	}
	if mo := i.MaintenanceOptions; mo != nil {
		if v := string(mo.AutoRecovery); v != "" {
			cfg["maintenance_options"] = []any{map[string]any{"auto_recovery": v}}
		}
	}
	if pd := i.PrivateDnsNameOptions; pd != nil {
		m := map[string]any{}
		if pd.EnableResourceNameDnsARecord != nil {
			m["enable_resource_name_dns_a_record"] = *pd.EnableResourceNameDnsARecord
		}
		if pd.EnableResourceNameDnsAAAARecord != nil {
			m["enable_resource_name_dns_aaaa_record"] = *pd.EnableResourceNameDnsAAAARecord
		}
		if v := string(pd.HostnameType); v != "" {
			m["hostname_type"] = v
		}
		if len(m) > 0 {
			cfg["private_dns_name_options"] = []any{m}
		}
	}
	if crs := i.CapacityReservationSpecification; crs != nil {
		m := map[string]any{}
		if v := string(crs.CapacityReservationPreference); v != "" {
			m["capacity_reservation_preference"] = v
		}
		if t := crs.CapacityReservationTarget; t != nil {
			tm := map[string]any{}
			if v := aws.ToString(t.CapacityReservationId); v != "" {
				tm["capacity_reservation_id"] = v
			}
			if v := aws.ToString(t.CapacityReservationResourceGroupArn); v != "" {
				tm["capacity_reservation_resource_group_arn"] = v
			}
			if len(tm) > 0 {
				m["capacity_reservation_target"] = []any{tm}
			}
		}
		if len(m) > 0 {
			cfg["capacity_reservation_specification"] = []any{m}
		}
	}
	if blocks := instanceBlockDevices(ctx, c, r.Region, i); blocks != nil {
		if blocks.root != nil {
			cfg["root_block_device"] = []any{blocks.root}
		}
		if len(blocks.ebs) > 0 {
			cfg["ebs_block_device"] = blocks.ebs
		}
	}
	// disable_api_termination / disable_api_stop / instance_initiated_shutdown_behavior
	// aren't part of DescribeInstances either -- same per-attribute call as
	// user_data below, one InstanceAttributeName at a time.
	ec2c := ec2.NewFromConfig(c.Cfg(r.Region))
	if attr, aerr := ec2c.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: &r.ID, Attribute: ec2types.InstanceAttributeNameDisableApiTermination,
	}); aerr == nil && attr.DisableApiTermination != nil && attr.DisableApiTermination.Value != nil {
		cfg["disable_api_termination"] = *attr.DisableApiTermination.Value
	}
	if attr, aerr := ec2c.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: &r.ID, Attribute: ec2types.InstanceAttributeNameDisableApiStop,
	}); aerr == nil && attr.DisableApiStop != nil && attr.DisableApiStop.Value != nil {
		cfg["disable_api_stop"] = *attr.DisableApiStop.Value
	}
	if attr, aerr := ec2c.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: &r.ID, Attribute: ec2types.InstanceAttributeNameInstanceInitiatedShutdownBehavior,
	}); aerr == nil && attr.InstanceInitiatedShutdownBehavior != nil {
		if v := aws.ToString(attr.InstanceInitiatedShutdownBehavior.Value); v != "" {
			cfg["instance_initiated_shutdown_behavior"] = v
		}
	}
	// UserData isn't part of DescribeInstances -- it's a separate
	// per-attribute call, and AWS always returns it base64-encoded. The
	// provider's Read decodes it into user_data when the result is valid
	// UTF-8 (falling back to user_data_base64 otherwise), so match that here
	// rather than always emitting the encoded form.
	if attr, aerr := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: &r.ID, Attribute: ec2types.InstanceAttributeNameUserData,
	}); aerr == nil && attr.UserData != nil && aws.ToString(attr.UserData.Value) != "" {
		enc := aws.ToString(attr.UserData.Value)
		if dec, derr := base64.StdEncoding.DecodeString(enc); derr == nil && utf8.Valid(dec) {
			cfg["user_data"] = string(dec)
		} else {
			cfg["user_data_base64"] = enc
		}
	}
	return cfg, nil
}

// instanceBlockDevices splits the instance's BlockDeviceMappings into the
// root device and the rest, matched against RootDeviceName the same way the
// provider's own Read does. InstanceBlockDeviceMapping/EbsInstanceBlockDevice
// only carry DeleteOnTermination and VolumeId -- size/type/iops/throughput/
// encrypted/kms_key_id all require a separate DescribeVolumes call, batched
// here into one request for every attached volume. A failure fetching
// volumes (or no volumes at all) degrades to nil, not an error -- the rest
// of the instance's config is still worth having.
func instanceBlockDevices(ctx context.Context, c *Clients, region string, i ec2types.Instance) *instanceBlocks {
	if len(i.BlockDeviceMappings) == 0 {
		return nil
	}
	var ids []string
	for _, bdm := range i.BlockDeviceMappings {
		if bdm.Ebs != nil && aws.ToString(bdm.Ebs.VolumeId) != "" {
			ids = append(ids, aws.ToString(bdm.Ebs.VolumeId))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	vols := map[string]ec2types.Volume{}
	out, err := ec2.NewFromConfig(c.Cfg(region)).DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: ids})
	if err == nil {
		for _, v := range out.Volumes {
			vols[aws.ToString(v.VolumeId)] = v
		}
	}

	root := aws.ToString(i.RootDeviceName)
	blocks := &instanceBlocks{}
	for _, bdm := range i.BlockDeviceMappings {
		if bdm.Ebs == nil {
			continue
		}
		name := aws.ToString(bdm.DeviceName)
		m := map[string]any{}
		if name != root {
			m["device_name"] = name
		}
		if bdm.Ebs.DeleteOnTermination != nil {
			m["delete_on_termination"] = *bdm.Ebs.DeleteOnTermination
		}
		if vol, ok := vols[aws.ToString(bdm.Ebs.VolumeId)]; ok {
			if vol.Size != nil {
				m["volume_size"] = *vol.Size
			}
			if v := string(vol.VolumeType); v != "" {
				m["volume_type"] = v
			}
			if vol.Iops != nil {
				m["iops"] = *vol.Iops
			}
			if vol.Throughput != nil {
				m["throughput"] = *vol.Throughput
			}
			if vol.Encrypted != nil {
				m["encrypted"] = *vol.Encrypted
			}
			if v := aws.ToString(vol.KmsKeyId); v != "" {
				m["kms_key_id"] = v
			}
			if v := aws.ToString(vol.SnapshotId); v != "" && name != root {
				m["snapshot_id"] = v
			}
		}
		if name == root {
			blocks.root = m
		} else {
			blocks.ebs = append(blocks.ebs, m)
		}
	}
	return blocks
}

type instanceBlocks struct {
	root map[string]any
	ebs  []any
}

// hydrateLaunchTemplate: DescribeLaunchTemplates only returns metadata
// (id/name/version numbers) -- none of a template's actual instance
// configuration (image_id, instance_type, block_device_mappings,
// network_interfaces, ...) lives there. That's ResponseLaunchTemplateData,
// returned only by DescribeLaunchTemplateVersions. LaunchTemplateName also
// doesn't snake-case to the schema's "name", so a plain Generic() call on
// the metadata response alone loses even that.
func hydrateLaunchTemplate(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_launch_template")
	if err != nil {
		return nil, err
	}
	cl := ec2.NewFromConfig(c.Cfg(r.Region))
	lt, err := cl.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{LaunchTemplateIds: []string{r.ID}})
	if err != nil {
		return nil, err
	}
	if len(lt.LaunchTemplates) == 0 {
		return nil, fmt.Errorf("not found")
	}
	meta := lt.LaunchTemplates[0]

	ver, err := cl.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: &r.ID,
		Versions:         []string{"$Default"},
	})
	if err != nil {
		return nil, err
	}
	if len(ver.LaunchTemplateVersions) == 0 || ver.LaunchTemplateVersions[0].LaunchTemplateData == nil {
		return nil, fmt.Errorf("no default version data for %s", r.ID)
	}
	v := ver.LaunchTemplateVersions[0]

	cfg, err := Generic(v.LaunchTemplateData, sch, nil)
	if err != nil {
		return nil, err
	}
	cfg["name"] = aws.ToString(meta.LaunchTemplateName)
	if d := aws.ToString(v.VersionDescription); d != "" {
		cfg["description"] = d
	}

	// Two fields Generic() can't reach on its own, both silently dropped
	// with no error:
	// (1) network_interfaces[].Groups (SDK) holds VPC security group ids,
	// but the schema's matching attribute is named "security_groups" (not
	// "security_group_ids", unlike a plain aws_instance) -- Generic()'s
	// snake_case name matching never finds it.
	// (2) tag_specifications[].Tags is []Tag in the SDK but the schema's
	// "tags" is map(string) -- the same IsMap()-passthrough gap
	// documented elsewhere in this package.
	if nis, ok := cfg["network_interfaces"].([]any); ok {
		for i, ni := range nis {
			if i >= len(v.LaunchTemplateData.NetworkInterfaces) {
				break
			}
			m, ok := ni.(map[string]any)
			if !ok {
				continue
			}
			if grp := v.LaunchTemplateData.NetworkInterfaces[i].Groups; len(grp) > 0 {
				sg := make([]any, len(grp))
				for j, g := range grp {
					sg[j] = g
				}
				m["security_groups"] = sg
			}
		}
	}
	if tss, ok := cfg["tag_specifications"].([]any); ok {
		for i, ts := range tss {
			if i >= len(v.LaunchTemplateData.TagSpecifications) {
				break
			}
			m, ok := ts.(map[string]any)
			if !ok {
				continue
			}
			tags := map[string]string{}
			for _, t := range v.LaunchTemplateData.TagSpecifications[i].Tags {
				if k := aws.ToString(t.Key); k != "" {
					tags[k] = aws.ToString(t.Value)
				}
			}
			if len(tags) > 0 {
				m["tags"] = tags
			}
		}
	}
	return cfg, nil
}

func hydrateASG(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := as.NewFromConfig(c.Cfg(r.Region)).DescribeAutoScalingGroups(ctx, &as.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.AutoScalingGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.AutoScalingGroups[0]
	cfg := map[string]any{
		"name":              aws.ToString(g.AutoScalingGroupName),
		"max_size":          aws.ToInt32(g.MaxSize),
		"min_size":          aws.ToInt32(g.MinSize),
		"desired_capacity":  aws.ToInt32(g.DesiredCapacity),
		"health_check_type": aws.ToString(g.HealthCheckType),
	}
	var subnets []any
	for _, s := range splitCSV(aws.ToString(g.VPCZoneIdentifier)) {
		subnets = append(subnets, s)
	}
	if len(subnets) > 0 {
		cfg["vpc_zone_identifier"] = subnets
	}
	if g.LaunchTemplate != nil {
		cfg["launch_template"] = map[string]any{
			"id":      aws.ToString(g.LaunchTemplate.LaunchTemplateId),
			"version": aws.ToString(g.LaunchTemplate.Version),
		}
	}
	// ASGs don't have a top-level tags map at all (the schema has no "tags"
	// attribute) -- every tag, including propagate_at_launch, only exists as
	// a repeatable tag{} block. DescribeAutoScalingGroups returns exactly
	// that shape directly; the registry's generic `cfg["tags"] = r.Tags`
	// (registry.go) is a silent no-op for this type (writeBlock drops
	// unrecognized top-level keys), so this was the only way any ASG tag,
	// let alone propagate_at_launch, could ever survive into config.
	var tags []any
	for _, t := range g.Tags {
		if strings.HasPrefix(aws.ToString(t.Key), "aws:") {
			continue
		}
		tags = append(tags, map[string]any{
			"key":                 aws.ToString(t.Key),
			"value":               aws.ToString(t.Value),
			"propagate_at_launch": aws.ToBool(t.PropagateAtLaunch),
		})
	}
	if len(tags) > 0 {
		cfg["tag"] = tags
	}
	return cfg, nil
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func hydrateBatchComputeEnv(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := batch.NewFromConfig(c.Cfg(r.Region)).DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{
		ComputeEnvironments: []string{name},
	})
	if err != nil {
		return nil, err
	}
	if len(out.ComputeEnvironments) == 0 {
		return nil, fmt.Errorf("not found")
	}
	ce := out.ComputeEnvironments[0]
	cfg := map[string]any{
		"compute_environment_name": aws.ToString(ce.ComputeEnvironmentName),
		"type":                     string(ce.Type),
	}
	if v := aws.ToString(ce.ServiceRole); v != "" {
		cfg["service_role"] = v
	}
	if v := string(ce.State); v != "" {
		cfg["state"] = v
	}
	if cr := ce.ComputeResources; cr != nil {
		res := map[string]any{
			"type":      string(cr.Type),
			"max_vcpus": aws.ToInt32(cr.MaxvCpus),
		}
		if cr.MinvCpus != nil {
			res["min_vcpus"] = *cr.MinvCpus
		}
		if len(cr.Subnets) > 0 {
			res["subnets"] = toAny(cr.Subnets)
		}
		if len(cr.SecurityGroupIds) > 0 {
			res["security_group_ids"] = toAny(cr.SecurityGroupIds)
		}
		if len(cr.InstanceTypes) > 0 {
			res["instance_type"] = toAny(cr.InstanceTypes)
		}
		if v := aws.ToString(cr.InstanceRole); v != "" {
			res["instance_role"] = v
		}
		cfg["compute_resources"] = res
	}
	return cfg, nil
}

func hydrateBatchJobQueue(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := batch.NewFromConfig(c.Cfg(r.Region)).DescribeJobQueues(ctx, &batch.DescribeJobQueuesInput{JobQueues: []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.JobQueues) == 0 {
		return nil, fmt.Errorf("not found")
	}
	q := out.JobQueues[0]
	cfg := map[string]any{
		"name":     aws.ToString(q.JobQueueName),
		"state":    string(q.State),
		"priority": aws.ToInt32(q.Priority),
	}
	var order []any
	for _, o := range q.ComputeEnvironmentOrder {
		order = append(order, map[string]any{
			"order":               aws.ToInt32(o.Order),
			"compute_environment": aws.ToString(o.ComputeEnvironment),
		})
	}
	if len(order) > 0 {
		cfg["compute_environment_order"] = order
	}
	return cfg, nil
}

func hydrateEMRCluster(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := emr.NewFromConfig(c.Cfg(r.Region)).DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: &id})
	if err != nil {
		return nil, err
	}
	cl := out.Cluster
	cfg := map[string]any{
		"name":          aws.ToString(cl.Name),
		"release_label": aws.ToString(cl.ReleaseLabel),
	}
	if v := aws.ToString(cl.ServiceRole); v != "" {
		cfg["service_role"] = v
	}
	if v := aws.ToString(cl.LogUri); v != "" {
		cfg["log_uri"] = v
	}
	if cl.Applications != nil {
		var apps []any
		for _, a := range cl.Applications {
			apps = append(apps, aws.ToString(a.Name))
		}
		cfg["applications"] = apps
	}
	if cl.Ec2InstanceAttributes != nil {
		ia := cl.Ec2InstanceAttributes
		attrs := map[string]any{}
		if v := aws.ToString(ia.Ec2SubnetId); v != "" {
			attrs["subnet_id"] = v
		}
		if v := aws.ToString(ia.IamInstanceProfile); v != "" {
			attrs["instance_profile"] = v
		}
		if v := aws.ToString(ia.EmrManagedMasterSecurityGroup); v != "" {
			attrs["emr_managed_master_security_group"] = v
		}
		if v := aws.ToString(ia.EmrManagedSlaveSecurityGroup); v != "" {
			attrs["emr_managed_slave_security_group"] = v
		}
		cfg["ec2_attributes"] = attrs
	}
	// DescribeCluster's Cluster doesn't carry instance group/fleet details at
	// all (a separate ListInstanceGroups/ListInstanceFleets call) -- without
	// this, master_instance_group/core_instance_group (or the fleet
	// equivalents) came back completely empty, so a real cluster's whole
	// instance configuration showed as dropped on every plan.
	// InstanceCollectionType tells us which shape this cluster actually
	// uses. TASK groups/fleets are deliberately excluded either way: the
	// provider models them as a separate aws_emr_instance_group /
	// aws_emr_instance_fleet resource, not a block here (and inherit doesn't
	// yet emit those as standalone resources -- a separate gap, tracked in
	// CLAUDE.md, not this one).
	if cl.InstanceCollectionType == emrtypes.InstanceCollectionTypeInstanceFleet {
		if err := hydrateEMRInstanceFleets(ctx, c, r, cfg); err != nil {
			return nil, err
		}
	} else {
		if err := hydrateEMRInstanceGroups(ctx, c, r, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// hydrateEMRInstanceFleets fills master_instance_fleet/core_instance_fleet
// for an INSTANCE_FLEET-type cluster -- the modern replacement for
// instance groups (mixed instance types/Spot+On-Demand within one fleet),
// a materially different, larger shape from hydrateEMRInstanceGroups.
func hydrateEMRInstanceFleets(ctx context.Context, c *Clients, r model.Resource, cfg map[string]any) error {
	cl := emr.NewFromConfig(c.Cfg(r.Region))
	p := emr.NewListInstanceFleetsPaginator(cl, &emr.ListInstanceFleetsInput{ClusterId: &r.ID})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, f := range page.InstanceFleets {
			var key string
			switch f.InstanceFleetType {
			case emrtypes.InstanceFleetTypeMaster:
				key = "master_instance_fleet"
			case emrtypes.InstanceFleetTypeCore:
				key = "core_instance_fleet"
			default:
				continue // TASK: separate aws_emr_instance_fleet resource, not a block here
			}
			m := map[string]any{}
			if v := aws.ToString(f.Name); v != "" {
				m["name"] = v
			}
			if f.TargetOnDemandCapacity != nil {
				m["target_on_demand_capacity"] = *f.TargetOnDemandCapacity
			}
			if f.TargetSpotCapacity != nil {
				m["target_spot_capacity"] = *f.TargetSpotCapacity
			}
			if len(f.InstanceTypeSpecifications) > 0 {
				var specs []any
				for _, s := range f.InstanceTypeSpecifications {
					sm := map[string]any{"instance_type": aws.ToString(s.InstanceType)}
					if s.WeightedCapacity != nil {
						sm["weighted_capacity"] = *s.WeightedCapacity
					}
					if v := aws.ToString(s.BidPrice); v != "" {
						sm["bid_price"] = v
					}
					if s.BidPriceAsPercentageOfOnDemandPrice != nil {
						sm["bid_price_as_percentage_of_on_demand_price"] = *s.BidPriceAsPercentageOfOnDemandPrice
					}
					if len(s.Configurations) > 0 {
						var confs []any
						for _, cf := range s.Configurations {
							cfm := map[string]any{}
							if v := aws.ToString(cf.Classification); v != "" {
								cfm["classification"] = v
							}
							if len(cf.Properties) > 0 {
								cfm["properties"] = cf.Properties
							}
							confs = append(confs, cfm)
						}
						sm["configurations"] = confs
					}
					if ebs := emrEbsConfig(s.EbsBlockDevices); len(ebs) > 0 {
						sm["ebs_config"] = ebs
					}
					specs = append(specs, sm)
				}
				m["instance_type_configs"] = specs
			}
			if ls := f.LaunchSpecifications; ls != nil {
				lsm := map[string]any{}
				if od := ls.OnDemandSpecification; od != nil {
					lsm["on_demand_specification"] = []any{map[string]any{
						"allocation_strategy": string(od.AllocationStrategy),
					}}
				}
				if sp := ls.SpotSpecification; sp != nil {
					spm := map[string]any{
						"timeout_action":           string(sp.TimeoutAction),
						"timeout_duration_minutes": aws.ToInt32(sp.TimeoutDurationMinutes),
						"allocation_strategy":      string(sp.AllocationStrategy),
					}
					if sp.BlockDurationMinutes != nil {
						spm["block_duration_minutes"] = *sp.BlockDurationMinutes
					}
					lsm["spot_specification"] = []any{spm}
				}
				if len(lsm) > 0 {
					m["launch_specifications"] = []any{lsm}
				}
			}
			cfg[key] = []any{m}
		}
	}
	return nil
}

func hydrateEMRInstanceGroups(ctx context.Context, c *Clients, r model.Resource, cfg map[string]any) error {
	cl := emr.NewFromConfig(c.Cfg(r.Region))
	p := emr.NewListInstanceGroupsPaginator(cl, &emr.ListInstanceGroupsInput{ClusterId: &r.ID})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, ig := range page.InstanceGroups {
			var key string
			switch ig.InstanceGroupType {
			case emrtypes.InstanceGroupTypeMaster:
				key = "master_instance_group"
			case emrtypes.InstanceGroupTypeCore:
				key = "core_instance_group"
			default:
				continue // TASK: separate aws_emr_instance_group resource, not a block here
			}
			m := map[string]any{"instance_type": aws.ToString(ig.InstanceType)}
			if v := aws.ToString(ig.Name); v != "" {
				m["name"] = v
			}
			if v := aws.ToString(ig.BidPrice); v != "" {
				m["bid_price"] = v
			}
			if ig.RequestedInstanceCount != nil {
				m["instance_count"] = *ig.RequestedInstanceCount
			}
			if ebs := emrEbsConfig(ig.EbsBlockDevices); len(ebs) > 0 {
				m["ebs_config"] = ebs
			}
			cfg[key] = []any{m}
		}
	}
	return nil
}

// emrEbsConfig flattens EbsBlockDevices into ebs_config set entries. AWS
// returns one EbsBlockDevice per actually-attached volume; the provider's own
// Read (flattenEBSConfig) groups identical specs (type/size/iops/throughput)
// into one ebs_config entry with volumes_per_instance set to the count --
// ebs_config is a Set, and volumes_per_instance is part of its hash, so N
// separate entries at volumes_per_instance=1 are N distinct set members, not
// the same thing as one entry at N. Device (the exposed device name) has no
// schema counterpart.
func emrEbsConfig(devs []emrtypes.EbsBlockDevice) []any {
	type key struct {
		typ                    string
		size, iops, throughput int32
	}
	counts := map[key]int{}
	var order []key
	for _, d := range devs {
		vs := d.VolumeSpecification
		if vs == nil {
			continue
		}
		k := key{typ: aws.ToString(vs.VolumeType), size: aws.ToInt32(vs.SizeInGB), iops: aws.ToInt32(vs.Iops), throughput: aws.ToInt32(vs.Throughput)}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	var out []any
	for _, k := range order {
		m := map[string]any{"type": k.typ, "size": k.size, "volumes_per_instance": counts[k]}
		if k.iops != 0 {
			m["iops"] = k.iops
		}
		if k.throughput != 0 {
			m["throughput"] = k.throughput
		}
		out = append(out, m)
	}
	return out
}

func hydrateEBApplication(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := elasticbeanstalk.NewFromConfig(c.Cfg(r.Region)).DescribeApplications(ctx, &elasticbeanstalk.DescribeApplicationsInput{
		ApplicationNames: []string{name},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Applications) == 0 {
		return nil, fmt.Errorf("not found")
	}
	a := out.Applications[0]
	cfg := map[string]any{"name": aws.ToString(a.ApplicationName)}
	if v := aws.ToString(a.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateEBEnvironment(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// r.ID is "<application>/<environment>"
	app, env, ok := strings.Cut(r.ID, "/")
	if !ok {
		env = r.ID
	}
	out, err := elasticbeanstalk.NewFromConfig(c.Cfg(r.Region)).DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
		EnvironmentNames: []string{env},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Environments) == 0 {
		return nil, fmt.Errorf("not found")
	}
	e := out.Environments[0]
	cfg := map[string]any{
		"name":        aws.ToString(e.EnvironmentName),
		"application": aws.ToString(e.ApplicationName),
	}
	if app != "" {
		cfg["application"] = app
	}
	if v := aws.ToString(e.SolutionStackName); v != "" {
		cfg["solution_stack_name"] = v
	}
	if v := aws.ToString(e.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(e.TemplateName); v != "" {
		cfg["template_name"] = v
	}
	if e.Tier != nil {
		if v := aws.ToString(e.Tier.Name); v != "" {
			cfg["tier"] = v
		}
	}
	return cfg, nil
}
