package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_ecr_repository", fanoutECRPolicies)
}

func fanoutECRPolicies(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := ecr.NewFromConfig(c.Cfg(parent.Region))
	repo := parent.ID
	var kids []model.Resource

	if lp, err := cl.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: &repo}); err == nil {
		kids = append(kids, model.Resource{
			Service: "ecr", Type: "lifecycle-policy", TFType: "aws_ecr_lifecycle_policy",
			Region: parent.Region, Account: parent.Account,
			ID:     repo,
			Config: map[string]any{"repository": repo, "policy": aws.ToString(lp.LifecyclePolicyText)},
		})
	}
	if rp, err := cl.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{RepositoryName: &repo}); err == nil {
		kids = append(kids, model.Resource{
			Service: "ecr", Type: "repository-policy", TFType: "aws_ecr_repository_policy",
			Region: parent.Region, Account: parent.Account,
			ID:     repo,
			Config: map[string]any{"repository": repo, "policy": aws.ToString(rp.PolicyText)},
		})
	}
	return kids, nil
}
