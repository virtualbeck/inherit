package hydrate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	dms "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_db_instance", hydrateDBInstance)
	register("aws_db_subnet_group", hydrateDBSubnetGroup)
	register("aws_rds_cluster", hydrateRDSCluster)
	register("aws_dynamodb_table", hydrateDynamoTable)
	register("aws_redshift_cluster", hydrateRedshift)
	register("aws_neptune_cluster", hydrateNeptune)
	register("aws_elasticache_cluster", hydrateElastiCache)
	register("aws_elasticache_replication_group", hydrateElastiCacheRG)
	register("aws_dms_replication_instance", hydrateDMSInstance)
	register("aws_memorydb_cluster", hydrateMemoryDBCluster)
	register("aws_db_proxy", hydrateDBProxy)
	register("aws_dms_endpoint", hydrateDMSEndpoint)
	register("aws_dms_replication_task", hydrateDMSReplicationTask)
	register("aws_dms_replication_subnet_group", hydrateDMSSubnetGroup)
	register("aws_elasticache_user", hydrateElastiCacheUser)
	register("aws_elasticache_user_group", hydrateElastiCacheUserGroup)
	register("aws_db_parameter_group", hydrateDBParamGroup)
	register("aws_rds_cluster_parameter_group", hydrateRDSClusterParamGroup)
	register("aws_db_option_group", hydrateDBOptionGroup)
	register("aws_elasticache_subnet_group", hydrateCacheSubnetGroup)
	register("aws_elasticache_parameter_group", hydrateCacheParamGroup)
}

func hydrateDBInstance(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_db_instance")
	if err != nil {
		return nil, err
	}
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: &r.ID,
	})
	if err != nil {
		return nil, err
	}
	if len(out.DBInstances) == 0 {
		return nil, fmt.Errorf("not found")
	}
	d := out.DBInstances[0]

	// Neptune instances come from the cluster fanout.
	if aws.ToString(d.Engine) == "neptune" {
		return nil, fmt.Errorf("neptune instance %q is emitted via aws_neptune_cluster_instance instead", r.ID)
	}

	cfg, err := Generic(d, sch, map[string]string{
		"db_instance_identifier":    "identifier",
		"db_instance_class":         "instance_class",
		"master_username":           "username",
		"db_instance_port":          "port",
		"iops":                      "iops",
		"ca_certificate_identifier": "ca_cert_identifier",
	})
	if err != nil {
		return nil, err
	}
	if d.DBSubnetGroup != nil {
		cfg["db_subnet_group_name"] = aws.ToString(d.DBSubnetGroup.DBSubnetGroupName)
	}
	if len(d.VpcSecurityGroups) > 0 {
		var ids []any
		for _, g := range d.VpcSecurityGroups {
			ids = append(ids, aws.ToString(g.VpcSecurityGroupId))
		}
		cfg["vpc_security_group_ids"] = ids
	}
	var pgs []any
	for _, p := range d.DBParameterGroups {
		pgs = append(pgs, aws.ToString(p.DBParameterGroupName))
	}
	if len(pgs) == 1 {
		cfg["parameter_group_name"] = pgs[0]
	}
	delete(cfg, "db_parameter_groups")
	delete(cfg, "vpc_security_groups")
	delete(cfg, "db_subnet_group")

	// DbInstancePort reads 0; use the endpoint port
	if d.Endpoint != nil && aws.ToInt32(d.Endpoint.Port) != 0 {
		cfg["port"] = aws.ToInt32(d.Endpoint.Port)
	} else {
		delete(cfg, "port")
	}
	// unrecoverable; matches the provider's import default
	cfg["skip_final_snapshot"] = true

	// inferred from MasterUserSecret
	if d.MasterUserSecret != nil {
		cfg["manage_master_user_password"] = true
		if v := aws.ToString(d.MasterUserSecret.KmsKeyId); v != "" {
			cfg["master_user_secret_kms_key_id"] = v
		}
	}
	return cfg, nil
}

func hydrateDBSubnetGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{
		DBSubnetGroupName: &r.ID,
	})
	if err != nil {
		return nil, err
	}
	if len(out.DBSubnetGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.DBSubnetGroups[0]
	cfg := map[string]any{
		"name":        aws.ToString(g.DBSubnetGroupName),
		"description": aws.ToString(g.DBSubnetGroupDescription),
	}
	var subnets []any
	for _, s := range g.Subnets {
		subnets = append(subnets, aws.ToString(s.SubnetIdentifier))
	}
	if len(subnets) > 0 {
		cfg["subnet_ids"] = subnets
	}
	return cfg, nil
}

// SDK names don't snake-case to several attributes.
func hydrateRDSCluster(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_rds_cluster")
	if err != nil {
		return nil, err
	}
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{DBClusterIdentifier: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.DBClusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	d := out.DBClusters[0]

	// Neptune shares this ARN segment; delegate to hydrateNeptune.
	if aws.ToString(d.Engine) == "neptune" {
		cfg, nerr := hydrateNeptune(ctx, c, r)
		if nerr != nil {
			return nil, nerr
		}
		cfg[retypeSentinel] = "aws_neptune_cluster"
		return cfg, nil
	}

	cfg, err := Generic(d, sch, map[string]string{
		"db_cluster_identifier":               "cluster_identifier",
		"db_subnet_group":                     "db_subnet_group_name",
		"db_cluster_parameter_group":          "db_cluster_parameter_group_name",
		"serverless_v2_scaling_configuration": "serverlessv2_scaling_configuration",
		"scaling_configuration_info":          "scaling_configuration",
	})
	if err != nil {
		return nil, err
	}

	if len(d.VpcSecurityGroups) > 0 {
		var ids []any
		for _, g := range d.VpcSecurityGroups {
			ids = append(ids, aws.ToString(g.VpcSecurityGroupId))
		}
		cfg["vpc_security_group_ids"] = ids
	}
	if len(d.AssociatedRoles) > 0 {
		var roles []any
		for _, ar := range d.AssociatedRoles {
			roles = append(roles, aws.ToString(ar.RoleArn))
		}
		cfg["iam_roles"] = roles
	}
	// unrecoverable; matches the provider's import default
	cfg["skip_final_snapshot"] = true
	return cfg, nil
}

// Keys flatten; PITR and TTL are separate calls.
func hydrateDynamoTable(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := dynamodb.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &r.ID})
	if err != nil {
		return nil, err
	}
	t := out.Table
	cfg := map[string]any{"name": aws.ToString(t.TableName)}
	if t.DeletionProtectionEnabled != nil {
		cfg["deletion_protection_enabled"] = *t.DeletionProtectionEnabled
	}
	if t.TableClassSummary != nil && t.TableClassSummary.TableClass != "" {
		cfg["table_class"] = string(t.TableClassSummary.TableClass)
	}

	if t.BillingModeSummary != nil && t.BillingModeSummary.BillingMode != "" {
		cfg["billing_mode"] = string(t.BillingModeSummary.BillingMode)
	}
	if t.ProvisionedThroughput != nil {
		if v := aws.ToInt64(t.ProvisionedThroughput.ReadCapacityUnits); v > 0 {
			cfg["read_capacity"] = v
		}
		if v := aws.ToInt64(t.ProvisionedThroughput.WriteCapacityUnits); v > 0 {
			cfg["write_capacity"] = v
		}
	}
	for _, k := range t.KeySchema {
		switch k.KeyType {
		case ddbtypes.KeyTypeHash:
			cfg["hash_key"] = aws.ToString(k.AttributeName)
		case ddbtypes.KeyTypeRange:
			cfg["range_key"] = aws.ToString(k.AttributeName)
		}
	}
	var attrs []any
	for _, a := range t.AttributeDefinitions {
		attrs = append(attrs, map[string]any{
			"name": aws.ToString(a.AttributeName),
			"type": string(a.AttributeType),
		})
	}
	if len(attrs) > 0 {
		cfg["attribute"] = attrs
	}

	var gsis []any
	for _, g := range t.GlobalSecondaryIndexes {
		gsi := map[string]any{"name": aws.ToString(g.IndexName)}
		for _, k := range g.KeySchema {
			switch k.KeyType {
			case ddbtypes.KeyTypeHash:
				gsi["hash_key"] = aws.ToString(k.AttributeName)
			case ddbtypes.KeyTypeRange:
				gsi["range_key"] = aws.ToString(k.AttributeName)
			}
		}
		if g.Projection != nil {
			gsi["projection_type"] = string(g.Projection.ProjectionType)
			if len(g.Projection.NonKeyAttributes) > 0 {
				gsi["non_key_attributes"] = toAny(g.Projection.NonKeyAttributes)
			}
		}
		if g.ProvisionedThroughput != nil {
			if v := aws.ToInt64(g.ProvisionedThroughput.ReadCapacityUnits); v > 0 {
				gsi["read_capacity"] = v
			}
			if v := aws.ToInt64(g.ProvisionedThroughput.WriteCapacityUnits); v > 0 {
				gsi["write_capacity"] = v
			}
		}
		gsis = append(gsis, gsi)
	}
	if len(gsis) > 0 {
		cfg["global_secondary_index"] = gsis
	}

	var lsis []any
	for _, l := range t.LocalSecondaryIndexes {
		lsi := map[string]any{"name": aws.ToString(l.IndexName)}
		for _, k := range l.KeySchema {
			if k.KeyType == ddbtypes.KeyTypeRange {
				lsi["range_key"] = aws.ToString(k.AttributeName)
			}
		}
		if l.Projection != nil {
			lsi["projection_type"] = string(l.Projection.ProjectionType)
			if len(l.Projection.NonKeyAttributes) > 0 {
				lsi["non_key_attributes"] = toAny(l.Projection.NonKeyAttributes)
			}
		}
		lsis = append(lsis, lsi)
	}
	if len(lsis) > 0 {
		cfg["local_secondary_index"] = lsis
	}

	if t.StreamSpecification != nil && aws.ToBool(t.StreamSpecification.StreamEnabled) {
		cfg["stream_enabled"] = true
		cfg["stream_view_type"] = string(t.StreamSpecification.StreamViewType)
	}
	if t.SSEDescription != nil && t.SSEDescription.Status == ddbtypes.SSEStatusEnabled {
		sse := map[string]any{"enabled": true}
		if k := aws.ToString(t.SSEDescription.KMSMasterKeyArn); k != "" {
			sse["kms_key_arn"] = k
		}
		cfg["server_side_encryption"] = sse
	}

	// always set: omitted reads as off
	if cb, err := cl.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: &r.ID}); err == nil && cb.ContinuousBackupsDescription != nil {
		if pitr := cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription; pitr != nil {
			cfg["point_in_time_recovery"] = map[string]any{
				"enabled": pitr.PointInTimeRecoveryStatus == ddbtypes.PointInTimeRecoveryStatusEnabled,
			}
		}
	}
	if tl, err := cl.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: &r.ID}); err == nil && tl.TimeToLiveDescription != nil {
		ttl := tl.TimeToLiveDescription
		cfg["ttl"] = map[string]any{
			"enabled":        ttl.TimeToLiveStatus == ddbtypes.TimeToLiveStatusEnabled,
			"attribute_name": aws.ToString(ttl.AttributeName),
		}
	}
	return cfg, nil
}

func hydrateRedshift(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := redshift.NewFromConfig(c.Cfg(r.Region)).DescribeClusters(ctx, &redshift.DescribeClustersInput{ClusterIdentifier: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.Clusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cl := out.Clusters[0]
	cfg := map[string]any{
		"cluster_identifier": aws.ToString(cl.ClusterIdentifier),
		"node_type":          aws.ToString(cl.NodeType),
		"database_name":      aws.ToString(cl.DBName),
		"master_username":    aws.ToString(cl.MasterUsername),
	}
	if n := aws.ToInt32(cl.NumberOfNodes); n != 0 {
		cfg["number_of_nodes"] = n
		if n == 1 {
			cfg["cluster_type"] = "single-node"
		} else {
			cfg["cluster_type"] = "multi-node"
		}
	}
	if cl.ClusterSubnetGroupName != nil {
		cfg["cluster_subnet_group_name"] = aws.ToString(cl.ClusterSubnetGroupName)
	}
	var sgs []any
	for _, g := range cl.VpcSecurityGroups {
		sgs = append(sgs, aws.ToString(g.VpcSecurityGroupId))
	}
	if len(sgs) > 0 {
		cfg["vpc_security_group_ids"] = sgs
	}
	if cl.Encrypted != nil {
		cfg["encrypted"] = *cl.Encrypted
	}
	if cl.Endpoint != nil && cl.Endpoint.Port != nil {
		cfg["port"] = *cl.Endpoint.Port
	}
	if cl.PubliclyAccessible != nil {
		cfg["publicly_accessible"] = *cl.PubliclyAccessible
	}
	if v := aws.ToString(cl.AvailabilityZone); v != "" {
		cfg["availability_zone"] = v
	}
	if cl.EnhancedVpcRouting != nil {
		cfg["enhanced_vpc_routing"] = *cl.EnhancedVpcRouting
	}
	if cl.AutomatedSnapshotRetentionPeriod != nil {
		cfg["automated_snapshot_retention_period"] = *cl.AutomatedSnapshotRetentionPeriod
	}
	if v := aws.ToString(cl.KmsKeyId); v != "" {
		cfg["kms_key_id"] = v
	}
	if len(cl.IamRoles) > 0 {
		var roles []any
		for _, ir := range cl.IamRoles {
			roles = append(roles, aws.ToString(ir.IamRoleArn))
		}
		cfg["iam_roles"] = roles
	}
	if len(cl.ClusterParameterGroups) > 0 {
		cfg["cluster_parameter_group_name"] = aws.ToString(cl.ClusterParameterGroups[0].ParameterGroupName)
	}
	return cfg, nil
}

// Same naming gaps as aws_rds_cluster.
func hydrateNeptune(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_neptune_cluster")
	if err != nil {
		return nil, err
	}
	out, err := neptune.NewFromConfig(c.Cfg(r.Region)).DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{DBClusterIdentifier: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.DBClusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	d := out.DBClusters[0]

	cfg, err := Generic(d, sch, map[string]string{
		"db_cluster_identifier":      "cluster_identifier",
		"db_subnet_group":            "neptune_subnet_group_name",
		"db_cluster_parameter_group": "neptune_cluster_parameter_group_name",
		"kms_key_id":                 "kms_key_arn",
	})
	if err != nil {
		return nil, err
	}
	if len(d.VpcSecurityGroups) > 0 {
		var ids []any
		for _, g := range d.VpcSecurityGroups {
			ids = append(ids, aws.ToString(g.VpcSecurityGroupId))
		}
		cfg["vpc_security_group_ids"] = ids
	}
	if len(d.AssociatedRoles) > 0 {
		var roles []any
		for _, ar := range d.AssociatedRoles {
			roles = append(roles, aws.ToString(ar.RoleArn))
		}
		cfg["iam_roles"] = roles
	}
	return cfg, nil
}

// SDK names diverge, cluster_id included.
func hydrateElastiCache(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_elasticache_cluster")
	if err != nil {
		return nil, err
	}
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{CacheClusterId: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.CacheClusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cc := out.CacheClusters[0]
	cfg, err := Generic(cc, sch, map[string]string{
		"cache_cluster_id":             "cluster_id",
		"cache_node_type":              "node_type",
		"preferred_maintenance_window": "maintenance_window",
		"cache_subnet_group_name":      "subnet_group_name",
	})
	if err != nil {
		return nil, err
	}
	if len(cc.SecurityGroups) > 0 {
		var ids []any
		for _, sg := range cc.SecurityGroups {
			ids = append(ids, aws.ToString(sg.SecurityGroupId))
		}
		cfg["security_group_ids"] = ids
	}
	if cc.CacheParameterGroup != nil {
		if v := aws.ToString(cc.CacheParameterGroup.CacheParameterGroupName); v != "" {
			cfg["parameter_group_name"] = v
		}
	}
	if cc.NotificationConfiguration != nil {
		if v := aws.ToString(cc.NotificationConfiguration.TopicArn); v != "" {
			cfg["notification_topic_arn"] = v
		}
	}
	return cfg, nil
}

// Tri-state strings to bools, plus nested fields.
func elastiCacheRGExtras(g ectypes.ReplicationGroup) map[string]any {
	out := map[string]any{}
	if v := string(g.AutomaticFailover); v != "" {
		out["automatic_failover_enabled"] = v == "enabled" || v == "enabling"
	}
	if v := string(g.MultiAZ); v != "" {
		out["multi_az_enabled"] = v == "enabled"
	}
	if v := string(g.DataTiering); v != "" {
		out["data_tiering_enabled"] = v == "enabled"
	}
	if g.ConfigurationEndpoint != nil {
		if v := aws.ToString(g.ConfigurationEndpoint.Address); v != "" {
			out["configuration_endpoint_address"] = v
		}
	}
	if g.GlobalReplicationGroupInfo != nil {
		if v := aws.ToString(g.GlobalReplicationGroupInfo.GlobalReplicationGroupId); v != "" {
			out["global_replication_group_id"] = v
		}
	}
	if len(g.NodeGroups) > 0 {
		out["num_node_groups"] = len(g.NodeGroups)
	}
	return out
}

func hydrateElastiCacheRG(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_elasticache_replication_group")
	if err != nil {
		return nil, err
	}
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{ReplicationGroupId: &r.ID})
	if err != nil {
		return nil, err
	}
	if len(out.ReplicationGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.ReplicationGroups[0]
	cfg, err := Generic(g, sch, map[string]string{"cache_node_type": "node_type"})
	if err != nil {
		return nil, err
	}
	maps.Copy(cfg, elastiCacheRGExtras(g))
	return cfg, nil
}

func hydrateDMSInstance(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := dms.NewFromConfig(c.Cfg(r.Region)).DescribeReplicationInstances(ctx, &dms.DescribeReplicationInstancesInput{
		Filters: []dmstypes.Filter{{Name: aws.String("replication-instance-arn"), Values: []string{arn}}},
	})
	if err != nil {
		return nil, err
	}
	if len(out.ReplicationInstances) == 0 {
		return nil, fmt.Errorf("not found")
	}
	ri := out.ReplicationInstances[0]
	cfg := map[string]any{
		"replication_instance_id":    aws.ToString(ri.ReplicationInstanceIdentifier),
		"replication_instance_class": aws.ToString(ri.ReplicationInstanceClass),
	}
	if ri.AllocatedStorage != 0 {
		cfg["allocated_storage"] = ri.AllocatedStorage
	}
	if ri.EngineVersion != nil {
		cfg["engine_version"] = aws.ToString(ri.EngineVersion)
	}
	cfg["multi_az"] = ri.MultiAZ
	cfg["publicly_accessible"] = ri.PubliclyAccessible
	if ri.ReplicationSubnetGroup != nil {
		cfg["replication_subnet_group_id"] = aws.ToString(ri.ReplicationSubnetGroup.ReplicationSubnetGroupIdentifier)
	}
	var sgs []any
	for _, g := range ri.VpcSecurityGroups {
		sgs = append(sgs, aws.ToString(g.VpcSecurityGroupId))
	}
	if len(sgs) > 0 {
		cfg["vpc_security_group_ids"] = sgs
	}
	return cfg, nil
}

func hydrateMemoryDBCluster(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := memorydb.NewFromConfig(c.Cfg(r.Region)).DescribeClusters(ctx, &memorydb.DescribeClustersInput{ClusterName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.Clusters) == 0 {
		return nil, fmt.Errorf("not found")
	}
	cl := out.Clusters[0]
	cfg := map[string]any{
		"name":      aws.ToString(cl.Name),
		"node_type": aws.ToString(cl.NodeType),
	}
	if v := aws.ToString(cl.ACLName); v != "" {
		cfg["acl_name"] = v
	}
	if cl.NumberOfShards != nil {
		cfg["num_shards"] = *cl.NumberOfShards
	}
	if v := aws.ToString(cl.SubnetGroupName); v != "" {
		cfg["subnet_group_name"] = v
	}
	if v := aws.ToString(cl.EngineVersion); v != "" {
		cfg["engine_version"] = v
	}
	if cl.TLSEnabled != nil {
		cfg["tls_enabled"] = *cl.TLSEnabled
	}
	var sgs []any
	for _, g := range cl.SecurityGroups {
		sgs = append(sgs, aws.ToString(g.SecurityGroupId))
	}
	if len(sgs) > 0 {
		cfg["security_group_ids"] = sgs
	}
	if v := aws.ToString(cl.Description); v != "" {
		cfg["description"] = v
	}
	if v := aws.ToString(cl.Engine); v != "" {
		cfg["engine"] = v
	}
	if v := aws.ToString(cl.KmsKeyId); v != "" {
		cfg["kms_key_arn"] = v
	}
	if v := aws.ToString(cl.MaintenanceWindow); v != "" {
		cfg["maintenance_window"] = v
	}
	if v := aws.ToString(cl.ParameterGroupName); v != "" {
		cfg["parameter_group_name"] = v
	}
	if v := string(cl.NetworkType); v != "" {
		cfg["network_type"] = v
	}
	if v := string(cl.IpDiscovery); v != "" {
		cfg["ip_discovery"] = v
	}
	if cl.ClusterEndpoint != nil && cl.ClusterEndpoint.Port != 0 {
		cfg["port"] = cl.ClusterEndpoint.Port
	}
	if cl.SnapshotRetentionLimit != nil {
		cfg["snapshot_retention_limit"] = *cl.SnapshotRetentionLimit
	}
	if v := aws.ToString(cl.SnapshotWindow); v != "" {
		cfg["snapshot_window"] = v
	}
	if v := aws.ToString(cl.SnsTopicArn); v != "" {
		cfg["sns_topic_arn"] = v
	}
	if cl.AutoMinorVersionUpgrade != nil {
		cfg["auto_minor_version_upgrade"] = *cl.AutoMinorVersionUpgrade
	}
	// API string enum; schema bool
	if v := string(cl.DataTiering); v != "" {
		cfg["data_tiering"] = v == "true"
	}
	if v := aws.ToString(cl.MultiRegionClusterName); v != "" {
		cfg["multi_region_cluster_name"] = v
	}
	return cfg, nil
}

func hydrateDBProxy(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{DBProxyName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.DBProxies) == 0 {
		return nil, fmt.Errorf("not found")
	}
	p := out.DBProxies[0]
	cfg := map[string]any{
		"name":           aws.ToString(p.DBProxyName),
		"engine_family":  aws.ToString(p.EngineFamily),
		"role_arn":       aws.ToString(p.RoleArn),
		"vpc_subnet_ids": toAny(p.VpcSubnetIds),
	}
	if aws.ToBool(p.RequireTLS) {
		cfg["require_tls"] = true
	}
	if p.IdleClientTimeout != nil {
		cfg["idle_client_timeout"] = *p.IdleClientTimeout
	}
	if aws.ToBool(p.DebugLogging) {
		cfg["debug_logging"] = true
	}
	var auths []any
	for _, a := range p.Auth {
		am := map[string]any{"auth_scheme": string(a.AuthScheme), "iam_auth": string(a.IAMAuth)}
		if v := aws.ToString(a.SecretArn); v != "" {
			am["secret_arn"] = v
		}
		if v := aws.ToString(a.Description); v != "" {
			am["description"] = v
		}
		auths = append(auths, am)
	}
	if len(auths) > 0 {
		cfg["auth"] = auths
	}
	return cfg, nil
}

func hydrateDMSEndpoint(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := dms.NewFromConfig(c.Cfg(r.Region)).DescribeEndpoints(ctx, &dms.DescribeEndpointsInput{
		Filters: []dmstypes.Filter{{Name: aws.String("endpoint-arn"), Values: []string{arn}}},
	})
	if err != nil || len(out.Endpoints) == 0 {
		return nil, fmt.Errorf("not found")
	}
	e := out.Endpoints[0]
	cfg := map[string]any{
		"endpoint_id":   aws.ToString(e.EndpointIdentifier),
		"endpoint_type": strings.ToLower(string(e.EndpointType)),
		"engine_name":   aws.ToString(e.EngineName),
	}
	if v := aws.ToString(e.ServerName); v != "" {
		cfg["server_name"] = v
	}
	if e.Port != nil {
		cfg["port"] = *e.Port
	}
	if v := aws.ToString(e.Username); v != "" {
		cfg["username"] = v
	}
	if v := aws.ToString(e.DatabaseName); v != "" {
		cfg["database_name"] = v
	}
	if v := aws.ToString(e.KmsKeyId); v != "" {
		cfg["kms_key_arn"] = v
	}
	if v := string(e.SslMode); v != "" {
		cfg["ssl_mode"] = v
	}
	// the engine settings blocks this schema models
	if sch, serr := schemaFor("aws_dms_endpoint"); serr == nil {
		for _, es := range []struct {
			key string
			val any
		}{
			{"mysql_settings", e.MySQLSettings},
			{"postgres_settings", e.PostgreSQLSettings},
			{"oracle_settings", e.OracleSettings},
			{"redshift_settings", e.RedshiftSettings},
			{"kinesis_settings", e.KinesisSettings},
			{"kafka_settings", e.KafkaSettings},
			{"mongodb_settings", e.MongoDbSettings},
			{"redis_settings", e.RedisSettings},
			{"elasticsearch_settings", e.ElasticsearchSettings},
		} {
			if reflect.ValueOf(es.val).IsNil() {
				continue
			}
			nb, ok := sch.NestedBlock(es.key)
			if !ok {
				continue
			}
			settings, gerr := Generic(es.val, nb.Block, nil)
			if gerr == nil && len(settings) > 0 {
				cfg[es.key] = []any{settings}
			}
		}
	}
	return cfg, nil
}

func hydrateDMSReplicationTask(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := dms.NewFromConfig(c.Cfg(r.Region)).DescribeReplicationTasks(ctx, &dms.DescribeReplicationTasksInput{
		Filters: []dmstypes.Filter{{Name: aws.String("replication-task-arn"), Values: []string{arn}}},
	})
	if err != nil || len(out.ReplicationTasks) == 0 {
		return nil, fmt.Errorf("not found")
	}
	t := out.ReplicationTasks[0]
	cfg := map[string]any{
		"replication_task_id":      aws.ToString(t.ReplicationTaskIdentifier),
		"migration_type":           string(t.MigrationType),
		"source_endpoint_arn":      aws.ToString(t.SourceEndpointArn),
		"target_endpoint_arn":      aws.ToString(t.TargetEndpointArn),
		"replication_instance_arn": aws.ToString(t.ReplicationInstanceArn),
		"table_mappings":           aws.ToString(t.TableMappings),
	}
	if v := aws.ToString(t.ReplicationTaskSettings); v != "" {
		cfg["replication_task_settings"] = v
	}
	if v := aws.ToString(t.CdcStartPosition); v != "" {
		cfg["cdc_start_position"] = v
	}
	return cfg, nil
}

func hydrateDMSSubnetGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := dms.NewFromConfig(c.Cfg(r.Region)).DescribeReplicationSubnetGroups(ctx, &dms.DescribeReplicationSubnetGroupsInput{
		Filters: []dmstypes.Filter{{Name: aws.String("replication-subnet-group-id"), Values: []string{id}}},
	})
	if err != nil || len(out.ReplicationSubnetGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.ReplicationSubnetGroups[0]
	var subs []any
	for _, s := range g.Subnets {
		subs = append(subs, aws.ToString(s.SubnetIdentifier))
	}
	return map[string]any{
		"replication_subnet_group_id":          aws.ToString(g.ReplicationSubnetGroupIdentifier),
		"replication_subnet_group_description": aws.ToString(g.ReplicationSubnetGroupDescription),
		"subnet_ids":                           subs,
	}, nil
}

func hydrateElastiCacheUser(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeUsers(ctx, &elasticache.DescribeUsersInput{UserId: &id})
	if err != nil || len(out.Users) == 0 {
		return nil, fmt.Errorf("not found")
	}
	u := out.Users[0]
	if aws.ToString(u.UserName) == "default" {
		return nil, fmt.Errorf("default user")
	}
	cfg := map[string]any{
		"user_id":       aws.ToString(u.UserId),
		"user_name":     aws.ToString(u.UserName),
		"engine":        aws.ToString(u.Engine),
		"access_string": aws.ToString(u.AccessString),
	}
	if len(u.Authentication.Type) > 0 {
		cfg["authentication_mode"] = map[string]any{"type": string(u.Authentication.Type)}
	}
	return cfg, nil
}

func hydrateElastiCacheUserGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeUserGroups(ctx, &elasticache.DescribeUserGroupsInput{UserGroupId: &id})
	if err != nil || len(out.UserGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.UserGroups[0]
	return map[string]any{
		"user_group_id": aws.ToString(g.UserGroupId),
		"engine":        aws.ToString(g.Engine),
		"user_ids":      toAny(g.UserIds),
	}, nil
}

func hydrateDBParamGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBParameterGroups(ctx, &rds.DescribeDBParameterGroupsInput{DBParameterGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.DBParameterGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.DBParameterGroups[0]
	cfg := map[string]any{
		"name":   aws.ToString(g.DBParameterGroupName),
		"family": aws.ToString(g.DBParameterGroupFamily),
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	// parameters are a separate call
	if params := dbParamGroupParams(ctx, rds.NewFromConfig(c.Cfg(r.Region)), name); len(params) > 0 {
		cfg["parameter"] = params
	}
	return cfg, nil
}

// userParam keeps Source "user" parameters only.
func userParam(source, name, value *string, applyMethod string) (map[string]any, bool) {
	if aws.ToString(source) != "user" {
		return nil, false
	}
	m := map[string]any{"name": aws.ToString(name), "value": aws.ToString(value)}
	if applyMethod != "" {
		m["apply_method"] = applyMethod
	}
	return m, true
}

func dbParamGroupParams(ctx context.Context, cl *rds.Client, name string) []any {
	var out []any
	p := rds.NewDescribeDBParametersPaginator(cl, &rds.DescribeDBParametersInput{DBParameterGroupName: &name})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			break
		}
		for _, prm := range page.Parameters {
			if m, ok := userParam(prm.Source, prm.ParameterName, prm.ParameterValue, string(prm.ApplyMethod)); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func hydrateRDSClusterParamGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeDBClusterParameterGroups(ctx, &rds.DescribeDBClusterParameterGroupsInput{DBClusterParameterGroupName: &name})
	if err != nil {
		// not RDS; Neptune shares this segment
		if _, ok := errors.AsType[*rdstypes.DBClusterParameterGroupNotFoundFault](err); !ok {
			return nil, err
		}
		return hydrateNeptuneClusterParamGroup(ctx, c, r)
	}
	if len(out.DBClusterParameterGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.DBClusterParameterGroups[0]
	cfg := map[string]any{
		"name":   aws.ToString(g.DBClusterParameterGroupName),
		"family": aws.ToString(g.DBParameterGroupFamily),
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	// parameters are a separate call
	if params := dbClusterParamGroupParams(ctx, rds.NewFromConfig(c.Cfg(r.Region)), name); len(params) > 0 {
		cfg["parameter"] = params
	}
	return cfg, nil
}

func hydrateNeptuneClusterParamGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	cl := neptune.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeDBClusterParameterGroups(ctx, &neptune.DescribeDBClusterParameterGroupsInput{DBClusterParameterGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.DBClusterParameterGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.DBClusterParameterGroups[0]
	cfg := map[string]any{
		retypeSentinel: "aws_neptune_cluster_parameter_group",
		"name":         aws.ToString(g.DBClusterParameterGroupName),
		"family":       aws.ToString(g.DBParameterGroupFamily),
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	var params []any
	p := neptune.NewDescribeDBClusterParametersPaginator(cl, &neptune.DescribeDBClusterParametersInput{DBClusterParameterGroupName: &name})
	for p.HasMorePages() {
		page, perr := p.NextPage(ctx)
		if perr != nil {
			break
		}
		for _, prm := range page.Parameters {
			if m, ok := userParam(prm.Source, prm.ParameterName, prm.ParameterValue, string(prm.ApplyMethod)); ok {
				params = append(params, m)
			}
		}
	}
	if len(params) > 0 {
		cfg["parameter"] = params
	}
	return cfg, nil
}

func dbClusterParamGroupParams(ctx context.Context, cl *rds.Client, name string) []any {
	var out []any
	p := rds.NewDescribeDBClusterParametersPaginator(cl, &rds.DescribeDBClusterParametersInput{DBClusterParameterGroupName: &name})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			break
		}
		for _, prm := range page.Parameters {
			if m, ok := userParam(prm.Source, prm.ParameterName, prm.ParameterValue, string(prm.ApplyMethod)); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func hydrateDBOptionGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := rds.NewFromConfig(c.Cfg(r.Region)).DescribeOptionGroups(ctx, &rds.DescribeOptionGroupsInput{OptionGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.OptionGroupsList) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.OptionGroupsList[0]
	cfg := map[string]any{
		"name":                     aws.ToString(g.OptionGroupName),
		"engine_name":              aws.ToString(g.EngineName),
		"major_engine_version":     aws.ToString(g.MajorEngineVersion),
		"option_group_description": aws.ToString(g.OptionGroupDescription),
	}
	var opts []any
	for _, o := range g.Options {
		m := map[string]any{"option_name": aws.ToString(o.OptionName)}
		if o.Port != nil {
			m["port"] = *o.Port
		}
		if len(o.VpcSecurityGroupMemberships) > 0 {
			var sgs []any
			for _, sg := range o.VpcSecurityGroupMemberships {
				sgs = append(sgs, aws.ToString(sg.VpcSecurityGroupId))
			}
			m["vpc_security_group_memberships"] = sgs
		}
		if len(o.DBSecurityGroupMemberships) > 0 {
			var sgs []any
			for _, sg := range o.DBSecurityGroupMemberships {
				sgs = append(sgs, aws.ToString(sg.DBSecurityGroupName))
			}
			m["db_security_group_memberships"] = sgs
		}
		if len(o.OptionSettings) > 0 {
			var settings []any
			for _, s := range o.OptionSettings {
				settings = append(settings, map[string]any{
					"name":  aws.ToString(s.Name),
					"value": aws.ToString(s.Value),
				})
			}
			m["option_settings"] = settings
		}
		opts = append(opts, m)
	}
	if len(opts) > 0 {
		cfg["option"] = opts
	}
	return cfg, nil
}

func hydrateCacheSubnetGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{CacheSubnetGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.CacheSubnetGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.CacheSubnetGroups[0]
	cfg := map[string]any{
		"name":        aws.ToString(g.CacheSubnetGroupName),
		"description": aws.ToString(g.CacheSubnetGroupDescription),
	}
	var subs []any
	for _, s := range g.Subnets {
		subs = append(subs, aws.ToString(s.SubnetIdentifier))
	}
	if len(subs) > 0 {
		cfg["subnet_ids"] = subs
	}
	return cfg, nil
}

func hydrateCacheParamGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := elasticache.NewFromConfig(c.Cfg(r.Region)).DescribeCacheParameterGroups(ctx, &elasticache.DescribeCacheParameterGroupsInput{CacheParameterGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.CacheParameterGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.CacheParameterGroups[0]
	cfg := map[string]any{
		"name":   aws.ToString(g.CacheParameterGroupName),
		"family": aws.ToString(g.CacheParameterGroupFamily),
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	// parameters are a separate call
	if params := cacheParamGroupParams(ctx, elasticache.NewFromConfig(c.Cfg(r.Region)), name); len(params) > 0 {
		cfg["parameter"] = params
	}
	return cfg, nil
}

func cacheParamGroupParams(ctx context.Context, cl *elasticache.Client, name string) []any {
	var out []any
	p := elasticache.NewDescribeCacheParametersPaginator(cl, &elasticache.DescribeCacheParametersInput{CacheParameterGroupName: &name})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			break
		}
		for _, prm := range page.Parameters {
			if m, ok := userParam(prm.Source, prm.ParameterName, prm.ParameterValue, ""); ok {
				out = append(out, m)
			}
		}
	}
	return out
}
