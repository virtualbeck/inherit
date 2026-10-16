package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGlobalGapFiller(gapFillIAM) }

// AWS-managed roles aren't imported.
const awsServiceLinkedRolePrefix = "/aws-service-role/"

// IAM Identity Center owns these; IAM refuses edits.
const awsReservedRolePrefix = "/aws-reserved/"

func awsManagedRole(path string) bool {
	return strings.HasPrefix(path, awsServiceLinkedRolePrefix) || strings.HasPrefix(path, awsReservedRolePrefix)
}

// The Tagging API never returns these IAM types.
func gapFillIAM(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := iam.NewFromConfig(c.Cfg(""))
	var out []model.Resource

	// gap-filled resources skip Run's tag step
	add := func(tfType, arn string, tags map[string]string) {
		segment := iamResourceSegment(tfType)
		_, id, _ := strings.Cut(arn, ":"+segment+"/")
		r := model.Resource{
			Service: "iam", Type: segment, TFType: tfType,
			ARN: arn, ID: id, Tags: tags,
		}
		cfg, finalType, err := hydrateRegistered(ctx, c, r)
		if err != nil || cfg == nil {
			return
		}
		if len(tags) > 0 {
			cfg["tags"] = tags
		}
		r.TFType = finalType
		r.Config = cfg
		out = append(out, r)
	}

	rp := iam.NewListRolesPaginator(cl, &iam.ListRolesInput{})
	for rp.HasMorePages() {
		page, err := rp.NextPage(ctx)
		if err != nil {
			break // no permission: skip, don't fail
		}
		for _, role := range page.Roles {
			if awsManagedRole(aws.ToString(role.Path)) {
				continue
			}
			// only GetRole returns tags
			var tags map[string]string
			if name := aws.ToString(role.RoleName); name != "" {
				if gr, gerr := cl.GetRole(ctx, &iam.GetRoleInput{RoleName: &name}); gerr == nil && gr.Role != nil {
					tags = iamTagMap(gr.Role.Tags)
				}
			}
			add("aws_iam_role", aws.ToString(role.Arn), tags)
		}
	}

	up := iam.NewListUsersPaginator(cl, &iam.ListUsersInput{})
	for up.HasMorePages() {
		page, err := up.NextPage(ctx)
		if err != nil {
			break
		}
		for _, u := range page.Users {
			// only GetUser returns tags
			var tags map[string]string
			if name := aws.ToString(u.UserName); name != "" {
				if gu, gerr := cl.GetUser(ctx, &iam.GetUserInput{UserName: &name}); gerr == nil && gu.User != nil {
					tags = iamTagMap(gu.User.Tags)
				}
			}
			add("aws_iam_user", aws.ToString(u.Arn), tags)
		}
	}

	gp := iam.NewListGroupsPaginator(cl, &iam.ListGroupsInput{})
	for gp.HasMorePages() {
		page, err := gp.NextPage(ctx)
		if err != nil {
			break
		}
		for _, g := range page.Groups {
			// groups don't support tags
			add("aws_iam_group", aws.ToString(g.Arn), nil)
		}
	}

	// customer-managed only
	pp := iam.NewListPoliciesPaginator(cl, &iam.ListPoliciesInput{Scope: "Local"})
	for pp.HasMorePages() {
		page, err := pp.NextPage(ctx)
		if err != nil {
			break
		}
		for _, p := range page.Policies {
			arn := aws.ToString(p.Arn)
			// policy tags are a separate call
			var tags map[string]string
			if lt, terr := cl.ListPolicyTags(ctx, &iam.ListPolicyTagsInput{PolicyArn: &arn}); terr == nil {
				tags = iamTagMap(lt.Tags)
			}
			add("aws_iam_policy", arn, tags)
		}
	}

	return out, nil
}

func iamTagMap(tags []iamtypes.Tag) map[string]string {
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

func iamResourceSegment(tfType string) string {
	switch tfType {
	case "aws_iam_role":
		return "role"
	case "aws_iam_user":
		return "user"
	case "aws_iam_group":
		return "group"
	case "aws_iam_policy":
		return "policy"
	default:
		return ""
	}
}
