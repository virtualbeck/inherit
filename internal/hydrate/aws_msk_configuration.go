package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { register("aws_msk_configuration", hydrateMSKConfiguration) }

func hydrateMSKConfiguration(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := kafka.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeConfiguration(ctx, &kafka.DescribeConfigurationInput{Arn: &r.ARN})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"name": aws.ToString(out.Name)}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if len(out.KafkaVersions) > 0 {
		cfg["kafka_versions"] = out.KafkaVersions
	}
	if out.LatestRevision != nil && out.LatestRevision.Revision != nil {
		rev, err := cl.DescribeConfigurationRevision(ctx, &kafka.DescribeConfigurationRevisionInput{
			Arn: &r.ARN, Revision: out.LatestRevision.Revision,
		})
		if err == nil {
			cfg["server_properties"] = string(rev.ServerProperties)
		}
	}
	return cfg, nil
}
