package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_dynamodb_table", fanoutDynamoDBReplicas)
}

// fanoutDynamoDBReplicas expands a global table into its additional-region
// replicas, a separate top-level resource in the provider (the table's own
// home region is the "main" replica, implicit in aws_dynamodb_table itself --
// not redeclared here). Each replica genuinely lives in its own region, so
// r.Region is set to that replica's real region for the multi-region
// provider-aliasing machinery, not the parent table's.
func fanoutDynamoDBReplicas(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	out, err := dynamodb.NewFromConfig(c.Cfg(parent.Region)).DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &parent.ID})
	if err != nil || out.Table == nil {
		return nil, err
	}
	globalARN := aws.ToString(out.Table.TableArn)
	var kids []model.Resource
	for _, rep := range out.Table.Replicas {
		region := aws.ToString(rep.RegionName)
		if region == "" || region == parent.Region {
			continue
		}
		cfg := map[string]any{"global_table_arn": globalARN}
		if rep.KMSMasterKeyId != nil {
			cfg["kms_key_arn"] = aws.ToString(rep.KMSMasterKeyId)
		}
		// A replica's tags are region-specific and not part of the home
		// region's DescribeTable response at all -- need ListTagsOfResource
		// against the replica's OWN regional ARN (same account/table name,
		// its own region segment), called with a client configured for
		// that region.
		var tags map[string]string
		if replicaARN := replicaTableARN(globalARN, region); replicaARN != "" {
			if lt, err := dynamodb.NewFromConfig(c.Cfg(region)).ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
				ResourceArn: &replicaARN,
			}); err == nil && len(lt.Tags) > 0 {
				tags = map[string]string{}
				for _, t := range lt.Tags {
					if k := aws.ToString(t.Key); k != "" {
						tags[k] = aws.ToString(t.Value)
					}
				}
				cfg["tags"] = tags
			}
		}
		kids = append(kids, model.Resource{
			Service: "dynamodb", Type: "table-replica", TFType: "aws_dynamodb_table_replica",
			Region: region, Account: parent.Account,
			ID: parent.ID + ":" + region, ImportID: parent.ID + ":" + region,
			Tags:   tags,
			Config: cfg,
		})
	}

	kids = append(kids, fanoutDynamoDBKinesisDestination(ctx, c, parent)...)
	kids = append(kids, fanoutDynamoDBContributorInsights(ctx, c, parent)...)

	return kids, nil
}

// fanoutDynamoDBKinesisDestination discovers an active Kinesis streaming
// destination on the table -- a separate top-level resource in the
// provider, one-to-one with the parent table (DynamoDB only supports one
// active Kinesis destination per table at a time), so at most one child.
// ENABLING/ACTIVE are the only statuses worth emitting: DISABLING/DISABLED
// mean the destination is going away or gone, and importing those into
// Terraform config would just recreate something the account owner already
// tore down.
func fanoutDynamoDBKinesisDestination(ctx context.Context, c *Clients, parent model.Resource) []model.Resource {
	cl := dynamodb.NewFromConfig(c.Cfg(parent.Region))
	out, err := cl.DescribeKinesisStreamingDestination(ctx, &dynamodb.DescribeKinesisStreamingDestinationInput{TableName: &parent.ID})
	if err != nil {
		return nil
	}
	var kids []model.Resource
	for _, d := range out.KinesisDataStreamDestinations {
		switch d.DestinationStatus {
		case ddbtypes.DestinationStatusActive, ddbtypes.DestinationStatusEnabling:
		default:
			continue
		}
		streamARN := aws.ToString(d.StreamArn)
		cfg := map[string]any{"table_name": parent.ID, "stream_arn": streamARN}
		if v := string(d.ApproximateCreationDateTimePrecision); v != "" {
			cfg["approximate_creation_date_time_precision"] = v
		}
		importID := parent.ID + "," + streamARN
		kids = append(kids, model.Resource{
			Service: "dynamodb", Type: "kinesis-streaming-destination", TFType: "aws_dynamodb_kinesis_streaming_destination",
			Region: parent.Region, Account: parent.Account,
			ID: importID, ImportID: importID,
			Config: cfg,
		})
	}
	return kids
}

// fanoutDynamoDBContributorInsights discovers contributor insights on the
// table itself and on each of its indexes independently -- ListContributorInsights
// returns one summary per table/index combination that has ever had it
// configured. Only ENABLED/ENABLING are emitted, same reasoning as the
// Kinesis destination above.
func fanoutDynamoDBContributorInsights(ctx context.Context, c *Clients, parent model.Resource) []model.Resource {
	cl := dynamodb.NewFromConfig(c.Cfg(parent.Region))
	var kids []model.Resource
	token := (*string)(nil)
	for {
		out, err := cl.ListContributorInsights(ctx, &dynamodb.ListContributorInsightsInput{TableName: &parent.ID, NextToken: token})
		if err != nil {
			break
		}
		for _, s := range out.ContributorInsightsSummaries {
			switch s.ContributorInsightsStatus {
			case ddbtypes.ContributorInsightsStatusEnabled, ddbtypes.ContributorInsightsStatusEnabling:
			default:
				continue
			}
			indexName := aws.ToString(s.IndexName)
			cfg := map[string]any{"table_name": parent.ID}
			if indexName != "" {
				cfg["index_name"] = indexName
			}
			// the provider's import ID is literally
			// "name:<table>/index:<indexName>/<accountID>" (empty
			// indexName segment for the table-level case).
			id := "name:" + parent.ID + "/index:" + indexName + "/" + parent.Account
			// mode isn't returned by List, only by Describe -- one extra
			// call per index, same shape as the kinesis destination's own
			// single-purpose Describe call above.
			if full, derr := cl.DescribeContributorInsights(ctx, &dynamodb.DescribeContributorInsightsInput{
				TableName: &parent.ID, IndexName: s.IndexName,
			}); derr == nil {
				if v := string(full.ContributorInsightsMode); v != "" {
					cfg["mode"] = v
				}
			}
			kids = append(kids, model.Resource{
				Service: "dynamodb", Type: "contributor-insights", TFType: "aws_dynamodb_contributor_insights",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	return kids
}

// replicaTableARN swaps the region segment of a table's home-region ARN
// ("arn:aws:dynamodb:REGION:ACCOUNT:table/NAME") for a replica's own region
// -- a DynamoDB global table replica is the same table name/account in a
// different region, so its ARN differs only in that one segment.
func replicaTableARN(homeARN, replicaRegion string) string {
	parts := strings.SplitN(homeARN, ":", 6)
	if len(parts) != 6 {
		return ""
	}
	parts[3] = replicaRegion
	return strings.Join(parts, ":")
}
