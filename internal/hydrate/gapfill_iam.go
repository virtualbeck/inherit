package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { registerGlobalGapFiller(gapFillIAM) }

// awsServiceLinkedRolePrefix marks a role AWS itself creates and manages
// (one per service that needs one, e.g. AWSServiceRoleForECS) -- these
// aren't meant to be imported into Terraform any more than an AWS-managed
// KMS key is (same exclusion precedent as hydrateKMSKey dropping those).
const awsServiceLinkedRolePrefix = "/aws-service-role/"

// gapFillIAM discovers IAM roles, users, groups, and customer-managed
// policies directly: resourcegroupstaggingapi's GetResources never returns
// any of these four types at all, tagged or not (aws_iam_instance_profile
// is the one IAM type it does return), so a standalone IAM role/user/group/
// policy is otherwise only ever found as a fanout child of something else
// that already referenced it (e.g. an EC2 instance's instance profile), or
// not at all. Reuses the existing registered hydrators (registry["aws_iam_*"])
// to build each resource's Config, so hydration logic isn't duplicated --
// this only replaces the *discovery* step the tagging API can't do.
func gapFillIAM(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := iam.NewFromConfig(c.Cfg(""))
	var out []model.Resource

	// add mirrors the main hydrate loop's own "cfgMap[\"tags\"] = r.Tags"
	// step (registry.go's Run): gap-filled resources skip that loop
	// entirely (Config is already set by the time Run sees them), and
	// Generic()'s filterBlock deliberately never reads tags off the raw
	// SDK payload (tagKeys are "handled from the discovery inventory,
	// never from the SDK payload") -- so without doing this here too,
	// every gap-filled resource's real tags would silently vanish.
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
			break // no iam:ListRoles permission or similar; skip, don't fail the whole scan
		}
		for _, role := range page.Roles {
			if strings.HasPrefix(aws.ToString(role.Path), awsServiceLinkedRolePrefix) {
				continue
			}
			// ListRoles' own entries never carry tags (the field exists on
			// the SDK struct but AWS never populates it for this summary
			// call) -- GetRole is the one that actually returns them.
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
			// same as roles above: ListUsers never returns tags, GetUser does.
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
			// ListGroups doesn't return tags at all (unlike roles/users) --
			// IAM groups don't support tagging as an API feature, not a
			// gap in this call.
			add("aws_iam_group", aws.ToString(g.Arn), nil)
		}
	}

	// Scope=Local: customer-managed policies only. AWS-managed policies
	// (arn:aws:iam::aws:policy/...) are a fixed, account-independent
	// catalog -- never something to import, same reasoning as excluding
	// service-linked roles above.
	pp := iam.NewListPoliciesPaginator(cl, &iam.ListPoliciesInput{Scope: "Local"})
	for pp.HasMorePages() {
		page, err := pp.NextPage(ctx)
		if err != nil {
			break
		}
		for _, p := range page.Policies {
			arn := aws.ToString(p.Arn)
			// unlike roles/users, ListPolicies doesn't embed tags -- a
			// separate per-policy call.
			var tags map[string]string
			if lt, terr := cl.ListPolicyTags(ctx, &iam.ListPolicyTagsInput{PolicyArn: &arn}); terr == nil {
				tags = iamTagMap(lt.Tags)
			}
			add("aws_iam_policy", arn, tags)
		}
	}

	return out, nil
}

// iamTagMap converts IAM's []Tag{Key,Value} into a plain map, the shape
// model.Resource.Tags and cfg["tags"] both expect.
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

// iamResourceSegment returns the ARN resource-type segment for one of the
// four TFTypes gapFillIAM handles, matching registry.go's arnToTF keys.
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
