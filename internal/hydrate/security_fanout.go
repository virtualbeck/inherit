package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_kms_key", fanoutKMSAliases)
	registerFanout("aws_secretsmanager_secret", fanoutSecretPolicy)
}

func fanoutKMSAliases(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := kms.NewFromConfig(c.Cfg(parent.Region))
	p := kms.NewListAliasesPaginator(cl, &kms.ListAliasesInput{KeyId: &parent.ID})
	var kids []model.Resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return kids, err
		}
		for _, a := range page.Aliases {
			name := aws.ToString(a.AliasName)
			if hasPrefix(name, "alias/aws/") {
				continue // AWS-managed alias, not importable
			}
			kids = append(kids, model.Resource{
				Service: "kms", Type: "alias", TFType: "aws_kms_alias",
				Region: parent.Region, Account: parent.Account,
				ID: name,
				Config: map[string]any{
					"name":          name,
					"target_key_id": parent.ID,
				},
			})
		}
	}
	return kids, nil
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func fanoutSecretPolicy(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := secretsmanager.NewFromConfig(c.Cfg(parent.Region))
	id := parent.ARN
	var kids []model.Resource

	if out, err := cl.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: &id}); err == nil && aws.ToString(out.ResourcePolicy) != "" {
		kids = append(kids, model.Resource{
			Service: "secretsmanager", Type: "secret-policy", TFType: "aws_secretsmanager_secret_policy",
			Region: parent.Region, Account: parent.Account, ID: parent.ARN,
			Config: map[string]any{"secret_arn": parent.ARN, "policy": aws.ToString(out.ResourcePolicy)},
		})
	}

	if d, err := cl.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: &id}); err == nil && aws.ToBool(d.RotationEnabled) {
		cfg := map[string]any{"secret_id": parent.ARN}
		if v := aws.ToString(d.RotationLambdaARN); v != "" {
			cfg["rotation_lambda_arn"] = v
		}
		if rr := d.RotationRules; rr != nil {
			rules := map[string]any{}
			if rr.AutomaticallyAfterDays != nil {
				rules["automatically_after_days"] = *rr.AutomaticallyAfterDays
			}
			if v := aws.ToString(rr.ScheduleExpression); v != "" {
				rules["schedule_expression"] = v
			}
			if v := aws.ToString(rr.Duration); v != "" {
				rules["duration"] = v
			}
			if len(rules) > 0 {
				cfg["rotation_rules"] = rules
			}
		}
		kids = append(kids, model.Resource{
			Service: "secretsmanager", Type: "secret-rotation", TFType: "aws_secretsmanager_secret_rotation",
			Region: parent.Region, Account: parent.Account, ID: parent.ARN,
			Config: cfg,
		})
	}
	return kids, nil
}
