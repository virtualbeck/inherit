package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	bktypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_backup_plan", fanoutBackupSelections)
	registerFanout("aws_backup_vault", fanoutBackupVaultSettings)
}

// fanoutBackupVaultSettings expands a backup vault into its access policy
// and notifications, both separate top-level resources in the provider and
// both optional per-vault settings -- most vaults have neither configured,
// so a NotFound-style error from either Get call just means "not set", not
// a real failure.
func fanoutBackupVaultSettings(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := backup.NewFromConfig(c.Cfg(parent.Region))
	name := parent.ID
	var kids []model.Resource

	if pol, err := cl.GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{BackupVaultName: &name}); err == nil && pol.Policy != nil {
		kids = append(kids, model.Resource{
			Service: "backup", Type: "vault-policy", TFType: "aws_backup_vault_policy",
			Region: parent.Region, Account: parent.Account,
			ID: name, ImportID: name,
			Config: map[string]any{"backup_vault_name": name, "policy": aws.ToString(pol.Policy)},
		})
	}

	if n, err := cl.GetBackupVaultNotifications(ctx, &backup.GetBackupVaultNotificationsInput{BackupVaultName: &name}); err == nil && n.SNSTopicArn != nil {
		var events []any
		for _, e := range n.BackupVaultEvents {
			events = append(events, string(e))
		}
		kids = append(kids, model.Resource{
			Service: "backup", Type: "vault-notifications", TFType: "aws_backup_vault_notifications",
			Region: parent.Region, Account: parent.Account,
			ID: name, ImportID: name,
			Config: map[string]any{
				"backup_vault_name": name, "sns_topic_arn": aws.ToString(n.SNSTopicArn),
				"backup_vault_events": events,
			},
		})
	}

	return kids, nil
}

// fanoutBackupSelections expands a backup plan into its resource selections,
// a separate top-level resource in the provider. Hand-built rather than
// Generic(): GetBackupSelection's SelectionName doesn't snake-case to the
// schema's "name", and Conditions/ListOfTags are shaped nothing like the
// schema's condition{}/selection_tag{} blocks (a single object of 4 lists,
// and a flat list, vs. repeatable {key,value}/{key,type,value} blocks).
func fanoutBackupSelections(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := backup.NewFromConfig(c.Cfg(parent.Region))
	planID := parent.ID

	var kids []model.Resource
	var token *string
	for {
		out, err := cl.ListBackupSelections(ctx, &backup.ListBackupSelectionsInput{BackupPlanId: &planID, NextToken: token})
		if err != nil {
			return kids, err
		}
		for _, m := range out.BackupSelectionsList {
			selID := aws.ToString(m.SelectionId)
			gs, err := cl.GetBackupSelection(ctx, &backup.GetBackupSelectionInput{BackupPlanId: &planID, SelectionId: &selID})
			if err != nil || gs.BackupSelection == nil {
				continue
			}
			s := gs.BackupSelection
			cfg := map[string]any{
				"name":         aws.ToString(s.SelectionName),
				"plan_id":      planID,
				"iam_role_arn": aws.ToString(s.IamRoleArn),
			}
			if len(s.Resources) > 0 {
				cfg["resources"] = toAny(s.Resources)
			}
			if len(s.NotResources) > 0 {
				cfg["not_resources"] = toAny(s.NotResources)
			}
			if tags := backupSelectionTags(s.ListOfTags); len(tags) > 0 {
				cfg["selection_tag"] = tags
			}
			if cond := backupSelectionCondition(s.Conditions); cond != nil {
				cfg["condition"] = []any{cond}
			}
			kids = append(kids, model.Resource{
				Service: "backup", Type: "selection", TFType: "aws_backup_selection",
				Region: parent.Region, Account: parent.Account,
				ID: selID, ImportID: planID + "|" + selID,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	return kids, nil
}

func backupSelectionTags(cs []bktypes.Condition) []any {
	var out []any
	for _, c := range cs {
		out = append(out, map[string]any{
			"key":   aws.ToString(c.ConditionKey),
			"type":  string(c.ConditionType),
			"value": aws.ToString(c.ConditionValue),
		})
	}
	return out
}

func backupSelectionCondition(c *bktypes.Conditions) map[string]any {
	if c == nil {
		return nil
	}
	build := func(ps []bktypes.ConditionParameter) []any {
		var out []any
		for _, p := range ps {
			out = append(out, map[string]any{
				"key":   aws.ToString(p.ConditionKey),
				"value": aws.ToString(p.ConditionValue),
			})
		}
		return out
	}
	m := map[string]any{}
	if v := build(c.StringEquals); len(v) > 0 {
		m["string_equals"] = v
	}
	if v := build(c.StringLike); len(v) > 0 {
		m["string_like"] = v
	}
	if v := build(c.StringNotEquals); len(v) > 0 {
		m["string_not_equals"] = v
	}
	if v := build(c.StringNotLike); len(v) > 0 {
		m["string_not_like"] = v
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
