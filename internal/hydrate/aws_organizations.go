package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_organizations_organizational_unit", hydrateOrgUnit)
	register("aws_organizations_policy", hydrateOrgPolicy)
	register("aws_organizations_account", hydrateOrgAccount)
}

func hydrateOrgUnit(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := lastPathSegment(r.ID)
	out, err := organizations.NewFromConfig(c.Cfg(r.Region)).DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{OrganizationalUnitId: &id})
	if err != nil || out.OrganizationalUnit == nil {
		return nil, err
	}
	ou := out.OrganizationalUnit
	cfg := map[string]any{"name": aws.ToString(ou.Name)}
	// parent_id has no Read equivalent on the OU object itself -- a
	// separate ListParents call against this OU's own ID.
	if p, perr := organizations.NewFromConfig(c.Cfg(r.Region)).ListParents(ctx, &organizations.ListParentsInput{ChildId: &id}); perr == nil && len(p.Parents) > 0 {
		if v := aws.ToString(p.Parents[0].Id); v != "" {
			cfg["parent_id"] = v
		}
	}
	return cfg, nil
}

func hydrateOrgPolicy(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := lastPathSegment(r.ID)
	out, err := organizations.NewFromConfig(c.Cfg(r.Region)).DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: &id})
	if err != nil || out.Policy == nil || out.Policy.PolicySummary == nil {
		return nil, err
	}
	ps := out.Policy.PolicySummary
	// an AWS-managed policy (e.g. the default FullAWSAccess SCP) can't be
	// created/managed by Terraform -- same exclusion precedent as
	// AWS-managed KMS keys and service-linked IAM roles elsewhere in this
	// package.
	if ps.AwsManaged {
		return nil, fmt.Errorf("AWS-managed organizations policy")
	}
	cfg := map[string]any{
		"name":    aws.ToString(ps.Name),
		"type":    string(ps.Type),
		"content": aws.ToString(out.Policy.Content),
	}
	if v := aws.ToString(ps.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateOrgAccount(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := lastPathSegment(r.ID)
	out, err := organizations.NewFromConfig(c.Cfg(r.Region)).DescribeAccount(ctx, &organizations.DescribeAccountInput{AccountId: &id})
	if err != nil || out.Account == nil {
		return nil, err
	}
	a := out.Account
	cfg := map[string]any{
		"name":  aws.ToString(a.Name),
		"email": aws.ToString(a.Email),
	}
	if p, perr := organizations.NewFromConfig(c.Cfg(r.Region)).ListParents(ctx, &organizations.ListParentsInput{ChildId: &id}); perr == nil && len(p.Parents) > 0 {
		if v := aws.ToString(p.Parents[0].Id); v != "" {
			cfg["parent_id"] = v
		}
	}
	return cfg, nil
}

// lastPathSegment returns the trailing "/"-delimited segment of an
// Organizations resource ID -- ARN resources here are "o-.../ou-..." or
// "o-.../account-id" or "o-.../policy-type/p-...", but the Describe* calls
// all just want the final ID, not the whole org-scoped path.
func lastPathSegment(id string) string {
	if i := lastSlash(id); i >= 0 {
		return id[i+1:]
	}
	return id
}
