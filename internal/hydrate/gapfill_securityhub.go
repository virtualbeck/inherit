package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGapFiller(gapFillSecurityHubAccount)
	registerGapFiller(gapFillSecurityHubFindingAggregator)
	registerGapFiller(gapFillSecurityHubStandardsSubscriptions)
	registerGapFiller(gapFillSecurityHubActionTargets)
	registerGapFiller(gapFillSecurityHubOrganizationConfiguration)
	registerGapFiller(gapFillSecurityHubMembers)
}

// gapFillSecurityHubAccount discovers whether Security Hub CSPM is enabled
// in this region: a true account/region singleton (DescribeHub takes no
// input), no ARN-based tagging concept the way most resources have one.
// DescribeHub errors (ResourceNotFoundException) when Security Hub isn't
// enabled here -- treated the same as ECR/Backup's other account-level
// gap-fillers skipping an unconfigured region, not a real failure.
func gapFillSecurityHubAccount(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	out, err := cl.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		return nil, nil
	}
	// enable_default_standards is a create-time-only, ForceNew directive
	// DescribeHub never returns -- confirmed against the real provider
	// source, whose own Read just re-sets whatever d.Get() already returns
	// rather than reading anything back. The schema declares
	// Default: true, which would suggest matching that -- but a real fresh
	// `--fast-import` run showed the opposite: the imported value always
	// comes back false regardless of that schema default (Defaults are
	// applied by Terraform core when planning a brand-new resource, not
	// by the provider's own Get() during an import's Read call, which
	// just sees the Go zero value for an unset bool). Matching the
	// EMPIRICALLY observed value here, not the schema's declared default
	// -- same "provider-only directive, no real Read" class as lambda's
	// publish/rds_cluster's skip_final_snapshot elsewhere in this
	// codebase, just with the opposite value from what reading the schema
	// alone would suggest.
	cfg := map[string]any{"enable_default_standards": false}
	if out.AutoEnableControls != nil {
		cfg["auto_enable_controls"] = *out.AutoEnableControls
	}
	if v := string(out.ControlFindingGenerator); v != "" {
		cfg["control_finding_generator"] = v
	}
	// the resource's real identity is the ACCOUNT id, not the region --
	// HubArn ("arn:aws:securityhub:region:account:hub/default") is a free
	// source for it without a separate STS call.
	account := ""
	if _, _, _, acct, _, ok := model.ParseARN(aws.ToString(out.HubArn)); ok {
		account = acct
	}
	if account == "" {
		return nil, nil
	}
	return []model.Resource{{
		Service: "securityhub", Type: "hub", TFType: "aws_securityhub_account",
		Region: region, ID: account, ImportID: account,
		Config: cfg,
	}}, nil
}

// gapFillSecurityHubFindingAggregator discovers the account's (at most one,
// per ListFindingAggregators' own doc comment) cross-region aggregation
// configuration.
func gapFillSecurityHubFindingAggregator(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	list, err := cl.ListFindingAggregators(ctx, &securityhub.ListFindingAggregatorsInput{})
	if err != nil || len(list.FindingAggregators) == 0 {
		return nil, nil
	}
	arn := aws.ToString(list.FindingAggregators[0].FindingAggregatorArn)
	if arn == "" {
		return nil, nil
	}
	det, err := cl.GetFindingAggregator(ctx, &securityhub.GetFindingAggregatorInput{FindingAggregatorArn: &arn})
	if err != nil {
		return nil, nil
	}
	cfg := map[string]any{}
	if v := aws.ToString(det.RegionLinkingMode); v != "" {
		cfg["linking_mode"] = v
	}
	if len(det.Regions) > 0 {
		cfg["specified_regions"] = toAny(det.Regions)
	}
	return []model.Resource{{
		Service: "securityhub", Type: "finding-aggregator", TFType: "aws_securityhub_finding_aggregator",
		Region: region, ID: arn, ImportID: arn,
		Config: cfg,
	}}, nil
}

// gapFillSecurityHubStandardsSubscriptions discovers which standards
// (CIS, PCI DSS, ...) are enabled -- multiple can exist, each independently
// enable/disable-able, no ARN-based tagging concept.
func gapFillSecurityHubStandardsSubscriptions(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.GetEnabledStandards(ctx, &securityhub.GetEnabledStandardsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, s := range page.StandardsSubscriptions {
			arn := aws.ToString(s.StandardsSubscriptionArn)
			if arn == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "securityhub", Type: "subscription", TFType: "aws_securityhub_standards_subscription",
				Region: region, ID: arn, ImportID: arn,
				Config: map[string]any{"standards_arn": aws.ToString(s.StandardsArn)},
			})
			out = append(out, securityHubStandardsControls(ctx, cl, region, arn)...)
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

// securityHubStandardsControls lists the individual controls within one
// enabled standard -- each control_status (ENABLED/DISABLED) is real,
// independently toggleable state, not something derivable from the
// subscription alone.
func securityHubStandardsControls(ctx context.Context, cl *securityhub.Client, region, subscriptionARN string) []model.Resource {
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.DescribeStandardsControls(ctx, &securityhub.DescribeStandardsControlsInput{
			StandardsSubscriptionArn: &subscriptionARN, NextToken: token,
		})
		if err != nil {
			return out
		}
		for _, sc := range page.Controls {
			arn := aws.ToString(sc.StandardsControlArn)
			if arn == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "securityhub", Type: "standards-control", TFType: "aws_securityhub_standards_control",
				Region: region, ID: arn, ImportID: arn,
				Config: map[string]any{
					"standards_control_arn": arn,
					"control_status":        string(sc.ControlStatus),
				},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out
}

// gapFillSecurityHubActionTargets discovers custom (user-defined) action
// targets -- DescribeActionTargets with no ActionTargetArns filter lists all
// of them; the built-in "send to Amazon Chime"/"send to Slack" and similar
// AWS-managed targets aren't returned here at all, only custom ones.
func gapFillSecurityHubActionTargets(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.DescribeActionTargets(ctx, &securityhub.DescribeActionTargetsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, at := range page.ActionTargets {
			arn := aws.ToString(at.ActionTargetArn)
			parts := strings.Split(arn, "/")
			if arn == "" || len(parts) != 3 {
				continue
			}
			out = append(out, model.Resource{
				Service: "securityhub", Type: "action-target", TFType: "aws_securityhub_action_target",
				Region: region, ID: arn, ImportID: arn,
				Config: map[string]any{
					"identifier":  parts[2],
					"name":        aws.ToString(at.Name),
					"description": aws.ToString(at.Description),
				},
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

// gapFillSecurityHubOrganizationConfiguration discovers the delegated
// admin's org-wide auto-enable settings -- a true account/region singleton
// (DescribeOrganizationConfiguration takes no input); errors (not the
// delegated admin, or Security Hub not enabled) are skipped like the other
// gap-fillers in this file.
func gapFillSecurityHubOrganizationConfiguration(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	out, err := cl.DescribeOrganizationConfiguration(ctx, &securityhub.DescribeOrganizationConfigurationInput{})
	if err != nil || out.AutoEnable == nil {
		return nil, nil
	}
	cfg := map[string]any{"auto_enable": *out.AutoEnable}
	if v := string(out.AutoEnableStandards); v != "" {
		cfg["auto_enable_standards"] = v
	}
	return []model.Resource{{
		Service: "securityhub", Type: "organization-configuration", TFType: "aws_securityhub_organization_configuration",
		Region: region, ID: region, ImportID: region,
		Config: cfg,
	}}, nil
}

// gapFillSecurityHubMembers discovers member accounts associated with this
// (administrator) account -- ListMembers/GetMembers, no ARN or tagging
// concept. email is Required by the schema but only populated for
// invitation-added members (per ListMembers' own doc comment), so an
// org-auto-associated member with no email is skipped, same judgment call
// as the GuardDuty member gap above.
func gapFillSecurityHubMembers(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := securityhub.NewFromConfig(c.Cfg(region))
	var ids []string
	token := (*string)(nil)
	for {
		page, err := cl.ListMembers(ctx, &securityhub.ListMembersInput{NextToken: token})
		if err != nil {
			return nil, nil
		}
		for _, m := range page.Members {
			if id := aws.ToString(m.AccountId); id != "" {
				ids = append(ids, id)
			}
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	if len(ids) == 0 {
		return nil, nil
	}
	got, err := cl.GetMembers(ctx, &securityhub.GetMembersInput{AccountIds: ids})
	if err != nil {
		return nil, nil
	}
	var out []model.Resource
	for _, m := range got.Members {
		accountID := aws.ToString(m.AccountId)
		email := aws.ToString(m.Email)
		if accountID == "" || email == "" {
			continue
		}
		out = append(out, model.Resource{
			Service: "securityhub", Type: "member", TFType: "aws_securityhub_member",
			Region: region, ID: accountID, ImportID: accountID,
			Config: map[string]any{"account_id": accountID, "email": email},
		})
	}
	return out, nil
}
