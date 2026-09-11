package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGapFiller(gapFillConfigRecorder) }

// gapFillConfigRecorder discovers the account's Config configuration
// recorder and delivery channel: true account-level singletons (one of
// each per region, no ARN-based tagging concept at all), so
// resourcegroupstaggingapi:GetResources has no path to ever find them --
// structurally, not a thin-coverage quirk like the IAM gap. Both are
// genuinely per-region (unlike IAM's account-global registerGlobalGapFiller),
// so a plain registerGapFiller running once per scanned region is correct
// here.
func gapFillConfigRecorder(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := configservice.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	if recs, err := cl.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{}); err == nil {
		for _, rec := range recs.ConfigurationRecorders {
			// Service-linked recorders (one per AWS service that needs
			// one) are AWS-managed, not something to import -- same
			// exclusion precedent as service-linked IAM roles and
			// AWS-managed KMS keys elsewhere in this package.
			if aws.ToString(rec.ServicePrincipal) != "" {
				continue
			}
			name := aws.ToString(rec.Name)
			if name == "" {
				continue
			}
			cfg := map[string]any{"role_arn": aws.ToString(rec.RoleARN)}
			if name != "default" {
				cfg["name"] = name
			}
			if rg := rec.RecordingGroup; rg != nil {
				rgm := map[string]any{
					"all_supported":                 rg.AllSupported,
					"include_global_resource_types": rg.IncludeGlobalResourceTypes,
				}
				if len(rg.ResourceTypes) > 0 {
					var rt []any
					for _, t := range rg.ResourceTypes {
						rt = append(rt, string(t))
					}
					rgm["resource_types"] = rt
				}
				cfg["recording_group"] = []any{rgm}
			}
			if rm := rec.RecordingMode; rm != nil && string(rm.RecordingFrequency) != "" {
				cfg["recording_mode"] = []any{map[string]any{
					"recording_frequency": string(rm.RecordingFrequency),
				}}
			}
			out = append(out, model.Resource{
				Service: "config", Type: "configuration-recorder", TFType: "aws_config_configuration_recorder",
				Region: region, ID: name, ImportID: name, Config: cfg,
			})
		}
	}

	if chans, err := cl.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{}); err == nil {
		for _, dc := range chans.DeliveryChannels {
			name := aws.ToString(dc.Name)
			if name == "" {
				continue
			}
			cfg := map[string]any{"s3_bucket_name": aws.ToString(dc.S3BucketName)}
			if name != "default" {
				cfg["name"] = name
			}
			if v := aws.ToString(dc.S3KeyPrefix); v != "" {
				cfg["s3_key_prefix"] = v
			}
			if v := aws.ToString(dc.S3KmsKeyArn); v != "" {
				cfg["s3_kms_key_arn"] = v
			}
			if v := aws.ToString(dc.SnsTopicARN); v != "" {
				cfg["sns_topic_arn"] = v
			}
			if sp := dc.ConfigSnapshotDeliveryProperties; sp != nil && string(sp.DeliveryFrequency) != "" {
				cfg["snapshot_delivery_properties"] = []any{map[string]any{
					"delivery_frequency": string(sp.DeliveryFrequency),
				}}
			}
			out = append(out, model.Resource{
				Service: "config", Type: "delivery-channel", TFType: "aws_config_delivery_channel",
				Region: region, ID: name, ImportID: name, Config: cfg,
			})
		}
	}

	return out, nil
}
