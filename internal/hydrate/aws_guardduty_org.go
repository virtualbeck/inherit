package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGlobalGapFiller(gapFillGuardDutyOrganizationAdminAccounts)
	register("aws_guardduty_malware_protection_plan", hydrateGuardDutyMalwareProtectionPlan)
	registerGapFiller(gapFillGuardDutyMalwareProtectionPlans)
}

// Global delegation; runs once, not per region.
func gapFillGuardDutyOrganizationAdminAccounts(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := guardduty.NewFromConfig(c.Cfg(""))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.ListOrganizationAdminAccounts(ctx, &guardduty.ListOrganizationAdminAccountsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, a := range page.AdminAccounts {
			id := aws.ToString(a.AdminAccountId)
			if id == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "guardduty", Type: "organization-admin-account", TFType: "aws_guardduty_organization_admin_account",
				ID: id, ImportID: id,
				Config: map[string]any{"admin_account_id": id},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

func hydrateGuardDutyMalwareProtectionPlan(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := guardduty.NewFromConfig(c.Cfg(r.Region)).GetMalwareProtectionPlan(ctx, &guardduty.GetMalwareProtectionPlanInput{MalwareProtectionPlanId: &id})
	if err != nil {
		return nil, err
	}
	if out.Role == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{"role": aws.ToString(out.Role)}
	if pr := out.ProtectedResource; pr != nil && pr.S3Bucket != nil {
		s3 := map[string]any{"bucket_name": aws.ToString(pr.S3Bucket.BucketName)}
		if len(pr.S3Bucket.ObjectPrefixes) > 0 {
			s3["object_prefixes"] = toAny(pr.S3Bucket.ObjectPrefixes)
		}
		cfg["protected_resource"] = []any{map[string]any{"s3_bucket": []any{s3}}}
	}
	if a := out.Actions; a != nil && a.Tagging != nil {
		cfg["actions"] = []any{map[string]any{
			"tagging": []any{map[string]any{"status": string(a.Tagging.Status)}},
		}}
	}
	if len(out.Tags) > 0 {
		cfg["tags"] = out.Tags
	}
	return cfg, nil
}

// Standalone malware plans; no discovery path otherwise.
func gapFillGuardDutyMalwareProtectionPlans(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := guardduty.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.ListMalwareProtectionPlans(ctx, &guardduty.ListMalwareProtectionPlansInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, p := range page.MalwareProtectionPlans {
			id := aws.ToString(p.MalwareProtectionPlanId)
			if id == "" {
				continue
			}
			cfg, herr := hydrateGuardDutyMalwareProtectionPlan(ctx, c, model.Resource{ID: id, Region: region})
			if herr != nil {
				continue
			}
			out = append(out, model.Resource{
				Service: "guardduty", Type: "malware-protection-plan", TFType: "aws_guardduty_malware_protection_plan",
				Region: region, ID: id, ImportID: id,
				Config: cfg,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}
