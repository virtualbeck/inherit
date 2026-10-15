package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/virtualbeck/inherit/internal/par"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillSSMExtras) }

// The documented setting IDs; there's no list API.
var knownSSMServiceSettingIDs = []string{
	"/ssm/appmanager/appmanager-enabled",
	"/ssm/automation/customer-script-log-destination",
	"/ssm/automation/customer-script-log-group-name",
	"/ssm/automation/enable-adaptive-concurrency",
	"/ssm/documents/console/public-sharing-permission",
	"/ssm/managed-instance/activation-tier",
	"/ssm/managed-instance/default-ec2-instance-management-role",
	"/ssm/opsinsights/opscenter",
	"/ssm/parameter-store/default-parameter-tier",
	"/ssm/parameter-store/high-throughput-enabled",
}

func gapFillSSMExtras(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := ssm.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	token := (*string)(nil)
	for {
		page, err := cl.ListResourceDataSync(ctx, &ssm.ListResourceDataSyncInput{NextToken: token})
		if err != nil {
			break
		}
		for _, s := range page.ResourceDataSyncItems {
			name := aws.ToString(s.SyncName)
			if name == "" {
				continue
			}
			cfg := map[string]any{"name": name}
			if s3d := s.S3Destination; s3d != nil {
				dest := map[string]any{
					"bucket_name": aws.ToString(s3d.BucketName),
					"region":      aws.ToString(s3d.Region),
					"sync_format": string(s3d.SyncFormat),
				}
				if v := aws.ToString(s3d.Prefix); v != "" {
					dest["prefix"] = v
				}
				if v := aws.ToString(s3d.AWSKMSKeyARN); v != "" {
					dest["kms_key_arn"] = v
				}
				if v := s3d.DestinationDataSharing; v != nil {
					dest["destination_data_sharing"] = []any{map[string]any{
						"destination_data_sharing_type": aws.ToString(v.DestinationDataSharingType),
					}}
				}
				cfg["s3_destination"] = []any{dest}
			}
			out = append(out, model.Resource{
				Service: "ssm", Type: "resource-data-sync", TFType: "aws_ssm_resource_data_sync",
				Region: region, ID: name, ImportID: name,
				Config: cfg,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}

	// independent reads, four at once, order kept
	settings := make([]*model.Resource, len(knownSSMServiceSettingIDs))
	idx := make([]int, len(knownSSMServiceSettingIDs))
	for i := range idx {
		idx[i] = i
	}
	par.Each(idx, 4, func(i int) {
		settingID := knownSSMServiceSettingIDs[i]
		s, err := cl.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{SettingId: &settingID})
		if err != nil || s.ServiceSetting == nil || aws.ToString(s.ServiceSetting.Status) != "Customized" {
			return
		}
		settings[i] = &model.Resource{
			Service: "ssm", Type: "servicesetting", TFType: "aws_ssm_service_setting",
			Region: region, ID: settingID, ImportID: settingID,
			Config: map[string]any{
				"setting_id":    settingID,
				"setting_value": aws.ToString(s.ServiceSetting.SettingValue),
			},
		}
	})
	for _, r := range settings {
		if r != nil {
			out = append(out, *r)
		}
	}

	return out, nil
}
