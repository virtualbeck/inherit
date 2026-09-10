package hydrate

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/virtualbeck/inherit-core/model"
)

// fanoutLambdaPermissions turns the resource policy of a function into one
// aws_lambda_permission per statement. Called from fanoutLambda.
func fanoutLambdaPermissions(ctx context.Context, cl *lambda.Client, parent model.Resource) []model.Resource {
	fn := parent.ID
	out, err := cl.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: &fn})
	if err != nil || out.Policy == nil {
		return nil
	}
	var doc struct {
		Statement []struct {
			Sid       string `json:"Sid"`
			Action    any    `json:"Action"`
			Principal any    `json:"Principal"`
			Condition map[string]map[string]any
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(*out.Policy), &doc) != nil {
		return nil
	}
	var kids []model.Resource
	for _, st := range doc.Statement {
		cfg := map[string]any{
			"statement_id":  st.Sid,
			"function_name": fn,
			"action":        firstString(st.Action),
		}
		switch p := st.Principal.(type) {
		case string:
			cfg["principal"] = p
		case map[string]any:
			if v, ok := p["Service"]; ok {
				cfg["principal"] = firstString(v)
			} else if v, ok := p["AWS"]; ok {
				cfg["principal"] = firstString(v)
			}
		}
		for _, ops := range st.Condition {
			if v, ok := ops["AWS:SourceArn"]; ok {
				cfg["source_arn"] = firstString(v)
			}
			if v, ok := ops["AWS:SourceAccount"]; ok {
				cfg["source_account"] = firstString(v)
			}
			// unlike SourceArn/SourceAccount, Lambda generates this one with
			// the AWS-standard lowercase "aws:" global-condition-key prefix.
			if v, ok := ops["aws:PrincipalOrgID"]; ok {
				cfg["principal_org_id"] = firstString(v)
			}
		}
		kids = append(kids, model.Resource{
			Service: "lambda", Type: "permission", TFType: "aws_lambda_permission",
			Region: parent.Region, Account: parent.Account,
			ID:     fn + "/" + st.Sid,
			Config: cfg,
		})
	}
	return kids
}
