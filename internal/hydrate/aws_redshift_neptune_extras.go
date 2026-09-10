package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_redshift_parameter_group", hydrateRedshiftParamGroup)
	register("aws_redshift_subnet_group", hydrateRedshiftSubnetGroup)
	register("aws_redshift_event_subscription", hydrateRedshiftEventSubscription)
	registerFanout("aws_neptune_cluster", fanoutNeptuneCluster)
	registerGlobalGapFiller(gapFillNeptuneEventSubscriptions)
}

func hydrateRedshiftParamGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	cl := redshift.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeClusterParameterGroups(ctx, &redshift.DescribeClusterParameterGroupsInput{ParameterGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.ParameterGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.ParameterGroups[0]
	cfg := map[string]any{
		"name":   aws.ToString(g.ParameterGroupName),
		"family": aws.ToString(g.ParameterGroupFamily),
	}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}

	var params []any
	marker := (*string)(nil)
	for {
		page, perr := cl.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{ParameterGroupName: &name, Marker: marker})
		if perr != nil {
			break
		}
		for _, prm := range page.Parameters {
			if aws.ToString(prm.Source) != "user" {
				continue
			}
			params = append(params, map[string]any{
				"name":  aws.ToString(prm.ParameterName),
				"value": aws.ToString(prm.ParameterValue),
			})
		}
		if page.Marker == nil || aws.ToString(page.Marker) == "" {
			break
		}
		marker = page.Marker
	}
	if len(params) > 0 {
		cfg["parameter"] = params
	}
	if len(g.Tags) > 0 {
		cfg["tags"] = redshiftTagMap(g.Tags)
	}
	return cfg, nil
}

func hydrateRedshiftSubnetGroup(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := redshift.NewFromConfig(c.Cfg(r.Region)).DescribeClusterSubnetGroups(ctx, &redshift.DescribeClusterSubnetGroupsInput{ClusterSubnetGroupName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.ClusterSubnetGroups) == 0 {
		return nil, fmt.Errorf("not found")
	}
	g := out.ClusterSubnetGroups[0]
	cfg := map[string]any{"name": aws.ToString(g.ClusterSubnetGroupName)}
	if v := aws.ToString(g.Description); v != "" {
		cfg["description"] = v
	}
	if len(g.Subnets) > 0 {
		ids := make([]string, 0, len(g.Subnets))
		for _, s := range g.Subnets {
			if id := aws.ToString(s.SubnetIdentifier); id != "" {
				ids = append(ids, id)
			}
		}
		cfg["subnet_ids"] = toAny(ids)
	}
	if len(g.Tags) > 0 {
		cfg["tags"] = redshiftTagMap(g.Tags)
	}
	return cfg, nil
}

func hydrateRedshiftEventSubscription(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	out, err := redshift.NewFromConfig(c.Cfg(r.Region)).DescribeEventSubscriptions(ctx, &redshift.DescribeEventSubscriptionsInput{SubscriptionName: &name})
	if err != nil {
		return nil, err
	}
	if len(out.EventSubscriptionsList) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.EventSubscriptionsList[0]
	cfg := map[string]any{
		"name":          aws.ToString(s.CustSubscriptionId),
		"sns_topic_arn": aws.ToString(s.SnsTopicArn),
		"enabled":       aws.ToBool(s.Enabled),
	}
	if v := aws.ToString(s.Severity); v != "" {
		cfg["severity"] = v
	}
	if v := aws.ToString(s.SourceType); v != "" {
		cfg["source_type"] = v
	}
	if len(s.SourceIdsList) > 0 {
		cfg["source_ids"] = toAny(s.SourceIdsList)
	}
	if len(s.EventCategoriesList) > 0 {
		cfg["event_categories"] = toAny(s.EventCategoriesList)
	}
	if len(s.Tags) > 0 {
		cfg["tags"] = redshiftTagMap(s.Tags)
	}
	return cfg, nil
}

func redshiftTagMap(tags []redshifttypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if k := aws.ToString(t.Key); k != "" {
			m[k] = aws.ToString(t.Value)
		}
	}
	return m
}

func neptuneTagMap(tags []neptunetypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if k := aws.ToString(t.Key); k != "" {
			m[k] = aws.ToString(t.Value)
		}
	}
	return m
}

// fanoutNeptuneCluster expands a Neptune cluster into its member instances
// and any custom cluster endpoints.
func fanoutNeptuneCluster(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := neptune.NewFromConfig(c.Cfg(parent.Region))
	clusterID := parent.ID
	var kids []model.Resource

	marker := (*string)(nil)
	for {
		page, err := cl.DescribeDBInstances(ctx, &neptune.DescribeDBInstancesInput{
			Filters: []neptunetypes.Filter{{Name: aws.String("db-cluster-id"), Values: []string{clusterID}}},
			Marker:  marker,
		})
		if err != nil {
			return kids, err
		}
		for _, inst := range page.DBInstances {
			id := aws.ToString(inst.DBInstanceIdentifier)
			if id == "" {
				continue
			}
			cfg := map[string]any{
				"identifier":         id,
				"cluster_identifier": clusterID,
				"instance_class":     aws.ToString(inst.DBInstanceClass),
			}
			if v := aws.ToString(inst.Engine); v != "" {
				cfg["engine"] = v
			}
			if len(inst.DBParameterGroups) > 0 {
				if v := aws.ToString(inst.DBParameterGroups[0].DBParameterGroupName); v != "" {
					cfg["neptune_parameter_group_name"] = v
				}
			}
			if inst.DBSubnetGroup != nil {
				if v := aws.ToString(inst.DBSubnetGroup.DBSubnetGroupName); v != "" {
					cfg["neptune_subnet_group_name"] = v
				}
			}
			// DBInstance carries no Tags field at all -- confirmed by a
			// real fresh import dropping every tag, not assumed. A
			// separate ListTagsForResource(arn) call is the only way to
			// get them, same as the cluster endpoint below.
			var tags map[string]string
			if arn := aws.ToString(inst.DBInstanceArn); arn != "" {
				if lt, terr := cl.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: &arn}); terr == nil {
					tags = neptuneTagMap(lt.TagList)
					if len(tags) > 0 {
						cfg["tags"] = tags
					}
				}
			}
			kids = append(kids, model.Resource{
				Service: "rds", Type: "db", TFType: "aws_neptune_cluster_instance",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Tags:   tags,
				Config: cfg,
			})
		}
		if page.Marker == nil || aws.ToString(page.Marker) == "" {
			break
		}
		marker = page.Marker
	}

	epMarker := (*string)(nil)
	for {
		page, err := cl.DescribeDBClusterEndpoints(ctx, &neptune.DescribeDBClusterEndpointsInput{DBClusterIdentifier: &clusterID, Marker: epMarker})
		if err != nil {
			return kids, err
		}
		for _, ep := range page.DBClusterEndpoints {
			epID := aws.ToString(ep.DBClusterEndpointIdentifier)
			epType := aws.ToString(ep.EndpointType)
			// CUSTOM endpoints are the only kind a user manages -- the
			// default "reader"/"writer" endpoints Neptune creates
			// automatically per cluster aren't separately importable
			// resources.
			if epID == "" || epType != "CUSTOM" {
				continue
			}
			id := clusterID + ":" + epID
			// EndpointType ("CUSTOM" here, already checked above) says WHO
			// created the endpoint; CustomEndpointType ("ANY"/"READER"/
			// "WRITER") is the schema's own endpoint_type -- the routing
			// behavior. Confirmed by a real tofu validate failure using
			// EndpointType for both ("expected endpoint_type to be one of
			// [ANY READER WRITER], got CUSTOM"), not assumed upfront.
			cfg := map[string]any{
				"cluster_endpoint_identifier": epID,
				"cluster_identifier":          clusterID,
				"endpoint_type":               aws.ToString(ep.CustomEndpointType),
			}
			if len(ep.StaticMembers) > 0 {
				cfg["static_members"] = toAny(ep.StaticMembers)
			}
			if len(ep.ExcludedMembers) > 0 {
				cfg["excluded_members"] = toAny(ep.ExcludedMembers)
			}
			// same tags gap as the cluster instance above: DBClusterEndpoint
			// carries no Tags field at all.
			var tags map[string]string
			if arn := aws.ToString(ep.DBClusterEndpointArn); arn != "" {
				if lt, terr := cl.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: &arn}); terr == nil {
					tags = neptuneTagMap(lt.TagList)
					if len(tags) > 0 {
						cfg["tags"] = tags
					}
				}
			}
			kids = append(kids, model.Resource{
				Service: "rds", Type: "cluster-endpoint", TFType: "aws_neptune_cluster_endpoint",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Tags:   tags,
				Config: cfg,
			})
		}
		if page.Marker == nil || aws.ToString(page.Marker) == "" {
			break
		}
		epMarker = page.Marker
	}

	return kids, nil
}

// gapFillNeptuneEventSubscriptions discovers Neptune event subscriptions
// directly via Neptune's own DescribeEventSubscriptions, sidestepping the
// ARN dispatch entirely: its ARN segment ("rds:es:name", confirmed against
// the real provider's own ARN check) is shared with RDS's own (currently
// unimplemented) event subscription type, and unlike cluster parameter
// groups there's no "NotFoundFault, so try the other service" signal to
// dispatch on cheaply -- DescribeEventSubscriptions succeeds either way,
// it just might return an empty list.
func gapFillNeptuneEventSubscriptions(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := neptune.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	marker := (*string)(nil)
	for {
		page, err := cl.DescribeEventSubscriptions(ctx, &neptune.DescribeEventSubscriptionsInput{Marker: marker})
		if err != nil {
			return out, nil
		}
		for _, s := range page.EventSubscriptionsList {
			name := aws.ToString(s.CustSubscriptionId)
			if name == "" {
				continue
			}
			cfg := map[string]any{
				"name":          name,
				"sns_topic_arn": aws.ToString(s.SnsTopicArn),
				"enabled":       aws.ToBool(s.Enabled),
			}
			if v := aws.ToString(s.SourceType); v != "" {
				cfg["source_type"] = v
			}
			if len(s.SourceIdsList) > 0 {
				cfg["source_ids"] = toAny(s.SourceIdsList)
			}
			if len(s.EventCategoriesList) > 0 {
				cfg["event_categories"] = toAny(s.EventCategoriesList)
			}
			out = append(out, model.Resource{
				Service: "rds", Type: "es", TFType: "aws_neptune_event_subscription",
				Region: region, ID: name, ImportID: name,
				Config: cfg,
			})
		}
		if page.Marker == nil || aws.ToString(page.Marker) == "" {
			break
		}
		marker = page.Marker
	}
	return out, nil
}
