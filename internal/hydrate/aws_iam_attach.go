package hydrate

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_iam_role", fanoutRole)
	registerFanout("aws_iam_user", fanoutUser)
	registerFanout("aws_iam_group", fanoutGroupAttachments)
}

// fanoutRole: managed-policy attachments + inline policies for a role.
func fanoutRole(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	kids, err := fanoutRoleAttachments(ctx, c, parent)
	if err != nil {
		return kids, err
	}
	name := baseName(parent.ID)
	cl := iam.NewFromConfig(c.Cfg(""))
	lp, err := cl.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &name})
	if err != nil {
		return kids, nil
	}
	for _, pn := range lp.PolicyNames {
		gp, err := cl.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &name, PolicyName: &pn})
		if err != nil {
			continue
		}
		doc := aws.ToString(gp.PolicyDocument)
		if d, err := url.QueryUnescape(doc); err == nil {
			doc = d
		}
		kids = append(kids, model.Resource{
			Service: "iam", Type: "role-policy", TFType: "aws_iam_role_policy",
			Account: parent.Account, ID: name + ":" + pn,
			Config: map[string]any{"name": pn, "role": name, "policy": doc},
		})
	}
	return kids, nil
}

// fanoutUser: managed-policy attachments + inline policies for a user.
func fanoutUser(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	kids, err := fanoutUserAttachments(ctx, c, parent)
	if err != nil {
		return kids, err
	}
	name := baseName(parent.ID)
	cl := iam.NewFromConfig(c.Cfg(""))
	lp, err := cl.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &name})
	if err != nil {
		return kids, nil
	}
	for _, pn := range lp.PolicyNames {
		gp, err := cl.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &name, PolicyName: &pn})
		if err != nil {
			continue
		}
		doc := aws.ToString(gp.PolicyDocument)
		if d, err := url.QueryUnescape(doc); err == nil {
			doc = d
		}
		kids = append(kids, model.Resource{
			Service: "iam", Type: "user-policy", TFType: "aws_iam_user_policy",
			Account: parent.Account, ID: name + ":" + pn,
			Config: map[string]any{"name": pn, "user": name, "policy": doc},
		})
	}
	if g, err := cl.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &name}); err == nil && len(g.Groups) > 0 {
		var groups []any
		imp := name
		for _, grp := range g.Groups {
			gn := aws.ToString(grp.GroupName)
			groups = append(groups, gn)
			imp += "/" + gn
		}
		kids = append(kids, model.Resource{
			Service: "iam", Type: "user-group-membership", TFType: "aws_iam_user_group_membership",
			Account: parent.Account, ID: name, ImportID: imp,
			Config: map[string]any{"user": name, "groups": groups},
		})
	}
	return kids, nil
}

func baseName(id string) string {
	if i := lastSlash(id); i >= 0 {
		return id[i+1:]
	}
	return id
}

func fanoutRoleAttachments(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	name := baseName(parent.ID)
	out, err := iam.NewFromConfig(c.Cfg("")).ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &name})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, p := range out.AttachedPolicies {
		arn := aws.ToString(p.PolicyArn)
		kids = append(kids, model.Resource{
			Service: "iam", Type: "role-policy-attachment", TFType: "aws_iam_role_policy_attachment",
			Account: parent.Account, ID: name + "/" + arn,
			Config: map[string]any{"role": name, "policy_arn": arn},
		})
	}
	return kids, nil
}

func fanoutUserAttachments(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	name := baseName(parent.ID)
	out, err := iam.NewFromConfig(c.Cfg("")).ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &name})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, p := range out.AttachedPolicies {
		arn := aws.ToString(p.PolicyArn)
		kids = append(kids, model.Resource{
			Service: "iam", Type: "user-policy-attachment", TFType: "aws_iam_user_policy_attachment",
			Account: parent.Account, ID: name + "/" + arn,
			Config: map[string]any{"user": name, "policy_arn": arn},
		})
	}
	return kids, nil
}

func fanoutGroupAttachments(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	name := baseName(parent.ID)
	cl := iam.NewFromConfig(c.Cfg(""))
	out, err := cl.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: &name})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, p := range out.AttachedPolicies {
		arn := aws.ToString(p.PolicyArn)
		kids = append(kids, model.Resource{
			Service: "iam", Type: "group-policy-attachment", TFType: "aws_iam_group_policy_attachment",
			Account: parent.Account, ID: name + "/" + arn,
			Config: map[string]any{"group": name, "policy_arn": arn},
		})
	}
	// Membership itself is emitted from the user side only (fanoutUser's
	// aws_iam_user_group_membership, one resource per user listing that
	// user's groups) -- not duplicated here as aws_iam_group_membership.
	// Both resources model the exact same real memberships, but each is an
	// exclusive-list type that fights the other on any future apply (the
	// provider's own docs warn against combining them); every pairing is
	// still fully covered from the user side, so nothing is lost by not
	// also emitting it from the group side.
	return kids, nil
}
