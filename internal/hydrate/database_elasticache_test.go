package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
)

// TestElastiCacheClusterOverrides guards against a Required-attribute drop:
// CacheCluster's CacheClusterId snake-cases to "cache_cluster_id", but the
// schema's attribute is just "cluster_id" -- Generic() silently drops it
// (and node_type/maintenance_window/subnet_group_name) with no error,
// leaving generated config missing its own Required identifying attribute.
func TestElastiCacheClusterOverrides(t *testing.T) {
	sch, err := schemaFor("aws_elasticache_cluster")
	if err != nil {
		t.Fatal(err)
	}
	cc := ectypes.CacheCluster{
		CacheClusterId:             aws.String("my-cluster"),
		CacheNodeType:              aws.String("cache.t3.micro"),
		Engine:                     aws.String("redis"),
		EngineVersion:              aws.String("7.0"),
		NumCacheNodes:              aws.Int32(1),
		PreferredMaintenanceWindow: aws.String("sun:05:00-sun:06:00"),
		CacheSubnetGroupName:       aws.String("my-subnet-group"),
	}
	cfg, err := Generic(cc, sch, map[string]string{
		"cache_cluster_id":             "cluster_id",
		"cache_node_type":              "node_type",
		"preferred_maintenance_window": "maintenance_window",
		"cache_subnet_group_name":      "subnet_group_name",
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"cluster_id":         "my-cluster",
		"node_type":          "cache.t3.micro",
		"maintenance_window": "sun:05:00-sun:06:00",
		"subnet_group_name":  "my-subnet-group",
	} {
		if got := cfg[k]; got != want {
			t.Errorf("cfg[%q] = %v, want %v", k, got, want)
		}
	}
}

func TestElastiCacheRGExtras(t *testing.T) {
	g := ectypes.ReplicationGroup{
		AutomaticFailover:     ectypes.AutomaticFailoverStatusEnabling,
		MultiAZ:               ectypes.MultiAZStatusDisabled,
		DataTiering:           ectypes.DataTieringStatusEnabled,
		ConfigurationEndpoint: &ectypes.Endpoint{Address: aws.String("my-rg.abc123.use1.cache.amazonaws.com")},
		GlobalReplicationGroupInfo: &ectypes.GlobalReplicationGroupInfo{
			GlobalReplicationGroupId: aws.String("my-global-store"),
		},
		NodeGroups: []ectypes.NodeGroup{{}, {}, {}},
	}
	out := elastiCacheRGExtras(g)

	if out["automatic_failover_enabled"] != true {
		t.Errorf("automatic_failover_enabled = %v, want true (enabling counts as on)", out["automatic_failover_enabled"])
	}
	if out["multi_az_enabled"] != false {
		t.Errorf("multi_az_enabled = %v, want false", out["multi_az_enabled"])
	}
	if out["data_tiering_enabled"] != true {
		t.Errorf("data_tiering_enabled = %v, want true", out["data_tiering_enabled"])
	}
	if out["configuration_endpoint_address"] != "my-rg.abc123.use1.cache.amazonaws.com" {
		t.Errorf("configuration_endpoint_address = %v", out["configuration_endpoint_address"])
	}
	if out["global_replication_group_id"] != "my-global-store" {
		t.Errorf("global_replication_group_id = %v", out["global_replication_group_id"])
	}
	if out["num_node_groups"] != 3 {
		t.Errorf("num_node_groups = %v, want 3", out["num_node_groups"])
	}
}
