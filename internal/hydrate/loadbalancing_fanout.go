package hydrate

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_lb_target_group", fanoutTargetGroupAttachments)
}

// fanoutTargetGroupAttachments emits an aws_lb_target_group_attachment per
// registered target.
func fanoutTargetGroupAttachments(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	out, err := elbv2.NewFromConfig(c.Cfg(parent.Region)).DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: &parent.ARN,
	})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, h := range out.TargetHealthDescriptions {
		if h.Target == nil {
			continue
		}
		tid := aws.ToString(h.Target.Id)
		cfg := map[string]any{
			"target_group_arn": parent.ARN,
			"target_id":        tid,
		}
		// the provider's import id for this type is
		// "TARGET_GROUP_ARN,TARGET_ID[,PORT][,AVAILABILITY_ZONE]" --
		// comma-separated, not slash-appended like every other
		// ARN-plus-suffix id in this file. availability_zone is only ever
		// returned when it was explicitly set at registration (an ip-type
		// target overriding zone affinity, most often the literal value
		// "all") -- without it here, such a target both drops real config
		// AND gets an import id one segment short of what the provider
		// expects.
		importID := parent.ARN + "," + tid
		if h.Target.Port != nil {
			cfg["port"] = *h.Target.Port
			importID += "," + strconv.FormatInt(int64(*h.Target.Port), 10)
		}
		if v := aws.ToString(h.Target.AvailabilityZone); v != "" {
			cfg["availability_zone"] = v
			if h.Target.Port == nil {
				importID += ","
			}
			importID += "," + v
		}
		kids = append(kids, model.Resource{
			Service: "elasticloadbalancing", Type: "target-group-attachment",
			TFType: "aws_lb_target_group_attachment", Region: parent.Region, Account: parent.Account,
			ID: importID, ImportID: importID, Config: cfg,
		})
	}
	return kids, nil
}
