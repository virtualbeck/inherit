package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_cognito_user_pool", fanoutCognitoClients)
}

// fanoutCognitoClients expands a user pool into its app clients.
func fanoutCognitoClients(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := cip.NewFromConfig(c.Cfg(parent.Region))
	pool := parent.ID
	var kids []model.Resource

	if d, err := cl.DescribeUserPool(ctx, &cip.DescribeUserPoolInput{UserPoolId: &pool}); err == nil && d.UserPool != nil {
		if dom := aws.ToString(d.UserPool.Domain); dom != "" {
			kids = append(kids, model.Resource{
				Service: "cognito-idp", Type: "userpooldomain", TFType: "aws_cognito_user_pool_domain",
				Region: parent.Region, Account: parent.Account, ID: dom, ImportID: dom,
				Config: map[string]any{"domain": dom, "user_pool_id": pool},
			})
		}
	}

	if g, err := cl.ListGroups(ctx, &cip.ListGroupsInput{UserPoolId: &pool}); err == nil {
		for _, grp := range g.Groups {
			gcfg := map[string]any{
				"user_pool_id": pool,
				"name":         aws.ToString(grp.GroupName),
			}
			if v := aws.ToString(grp.Description); v != "" {
				gcfg["description"] = v
			}
			if grp.Precedence != nil {
				gcfg["precedence"] = *grp.Precedence
			}
			if v := aws.ToString(grp.RoleArn); v != "" {
				gcfg["role_arn"] = v
			}
			kids = append(kids, model.Resource{
				Service: "cognito-idp", Type: "usergroup", TFType: "aws_cognito_user_group",
				Region: parent.Region, Account: parent.Account,
				ID:     pool + "/" + aws.ToString(grp.GroupName),
				Config: gcfg,
			})
		}
	}

	p := cip.NewListUserPoolClientsPaginator(cl, &cip.ListUserPoolClientsInput{
		UserPoolId: &pool, MaxResults: aws.Int32(60),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return kids, err
		}
		for _, ref := range page.UserPoolClients {
			id := aws.ToString(ref.ClientId)
			d, err := cl.DescribeUserPoolClient(ctx, &cip.DescribeUserPoolClientInput{UserPoolId: &pool, ClientId: &id})
			if err != nil {
				continue
			}
			uc := d.UserPoolClient
			cfg := map[string]any{
				"user_pool_id": pool,
				"name":         aws.ToString(uc.ClientName),
			}
			if aws.ToString(uc.ClientSecret) != "" {
				cfg["generate_secret"] = true
			}
			if len(uc.ExplicitAuthFlows) > 0 {
				var f []any
				for _, x := range uc.ExplicitAuthFlows {
					f = append(f, string(x))
				}
				cfg["explicit_auth_flows"] = f
			}
			if len(uc.CallbackURLs) > 0 {
				cfg["callback_urls"] = toAny(uc.CallbackURLs)
			}
			if len(uc.AllowedOAuthFlows) > 0 {
				var f []any
				for _, x := range uc.AllowedOAuthFlows {
					f = append(f, string(x))
				}
				cfg["allowed_oauth_flows"] = f
			}
			if len(uc.AllowedOAuthScopes) > 0 {
				cfg["allowed_oauth_scopes"] = toAny(uc.AllowedOAuthScopes)
			}
			if len(uc.SupportedIdentityProviders) > 0 {
				cfg["supported_identity_providers"] = toAny(uc.SupportedIdentityProviders)
			}
			if tvu := uc.TokenValidityUnits; tvu != nil {
				m := map[string]any{}
				if v := string(tvu.AccessToken); v != "" {
					m["access_token"] = v
				}
				if v := string(tvu.IdToken); v != "" {
					m["id_token"] = v
				}
				if v := string(tvu.RefreshToken); v != "" {
					m["refresh_token"] = v
				}
				if len(m) > 0 {
					cfg["token_validity_units"] = m
				}
			}
			kids = append(kids, model.Resource{
				Service: "cognito-idp", Type: "userpoolclient", TFType: "aws_cognito_user_pool_client",
				Region: parent.Region, Account: parent.Account,
				ID:     pool + "/" + id,
				Config: cfg,
			})
		}
	}
	return kids, nil
}
