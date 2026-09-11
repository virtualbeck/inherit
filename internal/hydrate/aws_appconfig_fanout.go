package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerFanout("aws_appconfig_application", fanoutAppConfigChildren) }

// fanoutAppConfigChildren expands an application into its environments and
// configuration profiles -- both nested under it (ARN
// application/<id>/environment|configurationprofile/<childId>), unlike
// deployment strategies, which are account-level and reusable across
// applications, so they're discovered independently via the normal
// tagging-API sweep instead (arnToTF), not here.
func fanoutAppConfigChildren(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := appconfig.NewFromConfig(c.Cfg(parent.Region))
	appID := parent.ID

	var kids []model.Resource

	envToken := (*string)(nil)
	for {
		out, err := cl.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: &appID, NextToken: envToken})
		if err != nil {
			break
		}
		for _, e := range out.Items {
			envID := aws.ToString(e.Id)
			cfg := map[string]any{
				"application_id": appID,
				"name":           aws.ToString(e.Name),
			}
			if v := aws.ToString(e.Description); v != "" {
				cfg["description"] = v
			}
			if len(e.Monitors) > 0 {
				var mons []any
				for _, m := range e.Monitors {
					mon := map[string]any{"alarm_arn": aws.ToString(m.AlarmArn)}
					if v := aws.ToString(m.AlarmRoleArn); v != "" {
						mon["alarm_role_arn"] = v
					}
					mons = append(mons, mon)
				}
				cfg["monitor"] = mons
			}
			arn := parent.ARN + "/environment/" + envID
			tags := appconfigTags(ctx, cl, arn)
			if len(tags) > 0 {
				cfg["tags"] = tags
			}
			// import id is "EnvironmentID:ApplicationID" -- not the
			// application-first/slash-joined shape the ARN's own path
			// would suggest.
			importID := envID + ":" + appID
			kids = append(kids, model.Resource{
				Service: "appconfig", Type: "environment", TFType: "aws_appconfig_environment",
				Region: parent.Region, Account: parent.Account,
				ARN: arn, ID: importID, ImportID: importID,
				Tags: tags, Config: cfg,
			})
		}
		if out.NextToken == nil {
			break
		}
		envToken = out.NextToken
	}

	profToken := (*string)(nil)
	for {
		out, err := cl.ListConfigurationProfiles(ctx, &appconfig.ListConfigurationProfilesInput{ApplicationId: &appID, NextToken: profToken})
		if err != nil {
			break
		}
		for _, p := range out.Items {
			profID := aws.ToString(p.Id)
			// the list summary is missing kms_key_identifier/retrieval_role_arn/
			// validator -- GetConfigurationProfile is the only way to get them.
			full, ferr := cl.GetConfigurationProfile(ctx, &appconfig.GetConfigurationProfileInput{
				ApplicationId: &appID, ConfigurationProfileId: &profID,
			})
			if ferr != nil {
				continue
			}
			cfg := map[string]any{
				"application_id": appID,
				"name":           aws.ToString(full.Name),
				"location_uri":   aws.ToString(full.LocationUri),
			}
			if v := aws.ToString(full.Description); v != "" {
				cfg["description"] = v
			}
			if v := aws.ToString(full.Type); v != "" {
				cfg["type"] = v
			}
			if v := aws.ToString(full.RetrievalRoleArn); v != "" {
				cfg["retrieval_role_arn"] = v
			}
			if v := aws.ToString(full.KmsKeyIdentifier); v != "" {
				cfg["kms_key_identifier"] = v
			}
			if len(full.Validators) > 0 {
				var vals []any
				for _, v := range full.Validators {
					vals = append(vals, map[string]any{
						"type": string(v.Type), "content": aws.ToString(v.Content),
					})
				}
				cfg["validator"] = vals
			}
			arn := parent.ARN + "/configurationprofile/" + profID
			tags := appconfigTags(ctx, cl, arn)
			if len(tags) > 0 {
				cfg["tags"] = tags
			}
			// import id is "ConfigurationProfileID:ApplicationID" --
			// same profile-first/colon-joined shape as the environment
			// case above.
			importID := profID + ":" + appID
			kids = append(kids, model.Resource{
				Service: "appconfig", Type: "configurationprofile", TFType: "aws_appconfig_configuration_profile",
				Region: parent.Region, Account: parent.Account,
				ARN: arn, ID: importID, ImportID: importID,
				Tags: tags, Config: cfg,
			})
		}
		if out.NextToken == nil {
			break
		}
		profToken = out.NextToken
	}

	return kids, nil
}

func appconfigTags(ctx context.Context, cl *appconfig.Client, arn string) map[string]string {
	out, err := cl.ListTagsForResource(ctx, &appconfig.ListTagsForResourceInput{ResourceArn: &arn})
	if err != nil {
		return nil
	}
	return out.Tags
}
