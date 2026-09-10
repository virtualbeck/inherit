package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_msk_cluster", fanoutMSKScramSecrets)
}

// fanoutMSKScramSecrets expands a cluster into its SASL/SCRAM secret
// association -- one resource per cluster (not per secret), listing every
// associated secret ARN as a set. Emits nothing when the cluster has none.
func fanoutMSKScramSecrets(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	var arns []string
	var token *string
	for {
		out, err := kafka.NewFromConfig(c.Cfg(parent.Region)).ListScramSecrets(ctx, &kafka.ListScramSecretsInput{
			ClusterArn: &parent.ARN, NextToken: token,
		})
		if err != nil {
			return nil, err
		}
		arns = append(arns, out.SecretArnList...)
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	if len(arns) == 0 {
		return nil, nil
	}
	return []model.Resource{{
		Service: "kafka", Type: "scram-secret-association", TFType: "aws_msk_scram_secret_association",
		Region: parent.Region, Account: parent.Account,
		ID: parent.ARN, ImportID: parent.ARN,
		Config: map[string]any{
			"cluster_arn":     parent.ARN,
			"secret_arn_list": toAny(arns),
		},
	}}, nil
}
