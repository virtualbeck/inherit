package hydrate

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_guardduty_detector", fanoutGuardDutyExtras)
}

func fanoutGuardDutyExtras(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := guardduty.NewFromConfig(c.Cfg(parent.Region))
	detectorID := parent.ID

	var kids []model.Resource

	var filterToken *string
	for {
		out, err := cl.ListFilters(ctx, &guardduty.ListFiltersInput{DetectorId: &detectorID, NextToken: filterToken})
		if err != nil {
			return kids, err
		}
		for _, name := range out.FilterNames {
			gf, err := cl.GetFilter(ctx, &guardduty.GetFilterInput{DetectorId: &detectorID, FilterName: &name})
			if err != nil {
				continue
			}
			cfg := map[string]any{
				"name":        name,
				"detector_id": detectorID,
				"action":      string(gf.Action),
				"rank":        aws.ToInt32(gf.Rank),
			}
			if v := aws.ToString(gf.Description); v != "" {
				cfg["description"] = v
			}
			if len(gf.Tags) > 0 {
				cfg["tags"] = gf.Tags
			}
			if gf.FindingCriteria != nil {
				if crit := guarddutyCriterion(gf.FindingCriteria.Criterion); len(crit) > 0 {
					cfg["finding_criteria"] = []any{map[string]any{"criterion": crit}}
				}
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "filter", TFType: "aws_guardduty_filter",
				Region: parent.Region, Account: parent.Account,
				ID: detectorID + ":" + name, ImportID: detectorID + ":" + name,
				Tags:   gf.Tags,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		filterToken = out.NextToken
	}

	// one feature resource per detector feature
	if det, err := cl.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &detectorID}); err == nil {
		for _, f := range det.Features {
			name := string(f.Name)
			// legacy always-on sources aren't valid feature names
			if name == "" || name == "FLOW_LOGS" || name == "CLOUD_TRAIL" || name == "DNS_LOGS" {
				continue
			}
			cfg := map[string]any{
				"detector_id": detectorID,
				"name":        name,
				"status":      string(f.Status),
			}
			if len(f.AdditionalConfiguration) > 0 {
				var acs []any
				for _, ac := range f.AdditionalConfiguration {
					acs = append(acs, map[string]any{"name": string(ac.Name), "status": string(ac.Status)})
				}
				cfg["additional_configuration"] = acs
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "detector-feature", TFType: "aws_guardduty_detector_feature",
				Region: parent.Region, Account: parent.Account,
				ID: detectorID + "/" + name, ImportID: detectorID + "/" + name,
				Config: cfg,
			})
		}
	}

	var destToken *string
	for {
		out, err := cl.ListPublishingDestinations(ctx, &guardduty.ListPublishingDestinationsInput{DetectorId: &detectorID, NextToken: destToken})
		if err != nil {
			return kids, err
		}
		for _, d := range out.Destinations {
			destID := aws.ToString(d.DestinationId)
			desc, err := cl.DescribePublishingDestination(ctx, &guardduty.DescribePublishingDestinationInput{
				DetectorId: &detectorID, DestinationId: &destID,
			})
			if err != nil || desc.DestinationProperties == nil {
				continue
			}
			cfg := map[string]any{
				"detector_id":      detectorID,
				"destination_type": string(desc.DestinationType),
				"kms_key_arn":      aws.ToString(desc.DestinationProperties.KmsKeyArn),
				"destination_arn":  aws.ToString(desc.DestinationProperties.DestinationArn),
			}
			if len(desc.Tags) > 0 {
				cfg["tags"] = desc.Tags
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "publishingdestination", TFType: "aws_guardduty_publishing_destination",
				Region: parent.Region, Account: parent.Account,
				ID: detectorID + ":" + destID, ImportID: detectorID + ":" + destID,
				Tags:   desc.Tags,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		destToken = out.NextToken
	}

	var ipToken *string
	for {
		out, err := cl.ListIPSets(ctx, &guardduty.ListIPSetsInput{DetectorId: &detectorID, NextToken: ipToken})
		if err != nil {
			return kids, err
		}
		for _, ipSetID := range out.IpSetIds {
			get, err := cl.GetIPSet(ctx, &guardduty.GetIPSetInput{DetectorId: &detectorID, IpSetId: &ipSetID})
			if err != nil {
				continue
			}
			id := detectorID + ":" + ipSetID
			cfg := map[string]any{
				"detector_id": detectorID,
				"activate":    get.Status == gdtypes.IpSetStatusActive,
				"format":      string(get.Format),
				"location":    aws.ToString(get.Location),
				"name":        aws.ToString(get.Name),
			}
			if len(get.Tags) > 0 {
				cfg["tags"] = get.Tags
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "ipset", TFType: "aws_guardduty_ipset",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Tags:   get.Tags,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		ipToken = out.NextToken
	}

	var tiToken *string
	for {
		out, err := cl.ListThreatIntelSets(ctx, &guardduty.ListThreatIntelSetsInput{DetectorId: &detectorID, NextToken: tiToken})
		if err != nil {
			return kids, err
		}
		for _, tiSetID := range out.ThreatIntelSetIds {
			get, err := cl.GetThreatIntelSet(ctx, &guardduty.GetThreatIntelSetInput{DetectorId: &detectorID, ThreatIntelSetId: &tiSetID})
			if err != nil {
				continue
			}
			id := detectorID + ":" + tiSetID
			cfg := map[string]any{
				"detector_id": detectorID,
				"activate":    get.Status == gdtypes.ThreatIntelSetStatusActive,
				"format":      string(get.Format),
				"location":    aws.ToString(get.Location),
				"name":        aws.ToString(get.Name),
			}
			if len(get.Tags) > 0 {
				cfg["tags"] = get.Tags
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "threatintelset", TFType: "aws_guardduty_threatintelset",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Tags:   get.Tags,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		tiToken = out.NextToken
	}

	var memberToken *string
	for {
		out, err := cl.ListMembers(ctx, &guardduty.ListMembersInput{DetectorId: &detectorID, NextToken: memberToken})
		if err != nil {
			return kids, err
		}
		for _, m := range out.Members {
			// email is required; invited members only
			email := aws.ToString(m.Email)
			accountID := aws.ToString(m.AccountId)
			if email == "" || accountID == "" {
				continue
			}
			id := detectorID + ":" + accountID
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "member", TFType: "aws_guardduty_member",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: map[string]any{
					"detector_id": detectorID,
					"account_id":  accountID,
					"email":       email,
				},
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		memberToken = out.NextToken
	}

	// works only on the delegated admin account
	if oc, err := cl.DescribeOrganizationConfiguration(ctx, &guardduty.DescribeOrganizationConfigurationInput{DetectorId: &detectorID}); err == nil {
		if v := string(oc.AutoEnableOrganizationMembers); v != "" {
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "organization-configuration", TFType: "aws_guardduty_organization_configuration",
				Region: parent.Region, Account: parent.Account,
				ID: detectorID, ImportID: detectorID,
				Config: map[string]any{
					"detector_id":                      detectorID,
					"auto_enable_organization_members": v,
				},
			})
		}
		for _, f := range oc.Features {
			name := string(f.Name)
			if name == "" {
				continue
			}
			id := detectorID + "/" + name
			cfg := map[string]any{
				"detector_id": detectorID,
				"name":        name,
				"auto_enable": string(f.AutoEnable),
			}
			if len(f.AdditionalConfiguration) > 0 {
				var acs []any
				for _, ac := range f.AdditionalConfiguration {
					acs = append(acs, map[string]any{
						"name":        string(ac.Name),
						"auto_enable": string(ac.AutoEnable),
					})
				}
				cfg["additional_configuration"] = acs
			}
			kids = append(kids, model.Resource{
				Service: "guardduty", Type: "organization-configuration-feature", TFType: "aws_guardduty_organization_configuration_feature",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	return kids, nil
}

// Criterion map to repeatable blocks; non-deprecated fields.
func guarddutyCriterion(m map[string]gdtypes.Condition) []any {
	var out []any
	for field, cond := range m {
		c := map[string]any{"field": field}
		if len(cond.Equals) > 0 {
			c["equals"] = toAny(cond.Equals)
		}
		if len(cond.NotEquals) > 0 {
			c["not_equals"] = toAny(cond.NotEquals)
		}
		if len(cond.Matches) > 0 {
			c["matches"] = toAny(cond.Matches)
		}
		if len(cond.NotMatches) > 0 {
			c["not_matches"] = toAny(cond.NotMatches)
		}
		if cond.GreaterThan != nil {
			c["greater_than"] = strconv.FormatInt(*cond.GreaterThan, 10)
		}
		if cond.GreaterThanOrEqual != nil {
			c["greater_than_or_equal"] = strconv.FormatInt(*cond.GreaterThanOrEqual, 10)
		}
		if cond.LessThan != nil {
			c["less_than"] = strconv.FormatInt(*cond.LessThan, 10)
		}
		if cond.LessThanOrEqual != nil {
			c["less_than_or_equal"] = strconv.FormatInt(*cond.LessThanOrEqual, 10)
		}
		out = append(out, c)
	}
	return out
}
