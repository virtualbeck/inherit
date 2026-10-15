package emit

import (
	"testing"

	"github.com/virtualbeck/inherit/model"
)

func TestImportID(t *testing.T) {
	cases := []struct {
		r    model.Resource
		want string
	}{
		{model.Resource{TFType: "aws_vpc", ID: "vpc-1"}, "vpc-1"},
		{model.Resource{TFType: "aws_s3_bucket", ID: "my-bucket"}, "my-bucket"},
		{model.Resource{TFType: "aws_iam_policy", ID: "p", ARN: "arn:aws:iam::1:policy/p"}, "arn:aws:iam::1:policy/p"},
		{model.Resource{TFType: "aws_sns_topic", ID: "t", ARN: "arn:aws:sns:us-east-1:1:t"}, "arn:aws:sns:us-east-1:1:t"},
		{model.Resource{TFType: "aws_sqs_queue", ID: "q", Region: "us-east-1", Account: "123"}, "https://sqs.us-east-1.amazonaws.com/123/q"},
		{model.Resource{TFType: "aws_sqs_queue", ID: "q"}, ""}, // no region/account -> skip
		{model.Resource{TFType: "aws_cloudformation_stack", ID: "MyStack/abc-123-uuid"}, "MyStack"},
		{model.Resource{TFType: "aws_cloudformation_stack_set", ID: "MySet:abc-123-uuid"}, "MySet"},
		{model.Resource{TFType: "aws_resourceexplorer2_index", ID: "uuid", ARN: "arn:aws:resource-explorer-2:us-west-1:1:index/uuid"}, "arn:aws:resource-explorer-2:us-west-1:1:index/uuid"},
		{model.Resource{TFType: "aws_resourceexplorer2_view", ID: "DefaultView/uuid", ARN: "arn:aws:resource-explorer-2:us-west-1:1:view/DefaultView/uuid"}, "arn:aws:resource-explorer-2:us-west-1:1:view/DefaultView/uuid"},
		{model.Resource{TFType: "aws_iam_openid_connect_provider", ID: "sts.windows.net/uuid", ARN: "arn:aws:iam::1:oidc-provider/sts.windows.net/uuid"}, "arn:aws:iam::1:oidc-provider/sts.windows.net/uuid"},
		{model.Resource{TFType: "aws_iam_saml_provider", ID: "MyProvider", ARN: "arn:aws:iam::1:saml-provider/MyProvider"}, "arn:aws:iam::1:saml-provider/MyProvider"},
		{model.Resource{TFType: "aws_secretsmanager_secret", ID: "app/db-password-AbC123", ARN: "arn:aws:secretsmanager:us-east-1:1:secret:app/db-password-AbC123"}, "arn:aws:secretsmanager:us-east-1:1:secret:app/db-password-AbC123"},
		{model.Resource{TFType: "aws_lb", ID: "app/my-alb/abc123", ARN: "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/my-alb/abc123"}, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/my-alb/abc123"},
		{model.Resource{TFType: "aws_lb_target_group", ID: "my-tg/abc123", ARN: "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/my-tg/abc123"}, "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/my-tg/abc123"},
		{model.Resource{TFType: "aws_acm_certificate", ID: "abc-uuid", ARN: "arn:aws:acm:us-east-1:1:certificate/abc-uuid"}, "arn:aws:acm:us-east-1:1:certificate/abc-uuid"},
		{model.Resource{TFType: "aws_lb_listener", ID: "app/my-alb/lbid/listenerid", ARN: "arn:aws:elasticloadbalancing:us-east-1:1:listener/app/my-alb/lbid/listenerid"}, "arn:aws:elasticloadbalancing:us-east-1:1:listener/app/my-alb/lbid/listenerid"},
		// r.ID ("family:revision") is the documented legacy import format
		// and looks like a perfectly valid id, but the provider now
		// requires the ARN for this type with no fallback -- confirmed
		// against a real account ("arn: invalid prefix", no diagnostic
		// context at all since it fails deep inside the provider's own
		// ARN-detection, not a surfaced validation).
		{model.Resource{TFType: "aws_ecs_task_definition", ID: "my-task:5", ARN: "arn:aws:ecs:us-east-1:1:task-definition/my-task:5"}, "arn:aws:ecs:us-east-1:1:task-definition/my-task:5"},
		// r.ID is the ARN's resource segment, which never carries a
		// hierarchical parameter's real leading "/" -- the hydrator already
		// resolved and confirmed the true name against the live API and put
		// it in Config, so importID must prefer that over re-guessing from ID.
		{model.Resource{TFType: "aws_ssm_parameter", ID: "tf/route53/baseline/zone_id",
			Config: map[string]any{"name": "/tf/route53/baseline/zone_id"}}, "/tf/route53/baseline/zone_id"},
		{model.Resource{TFType: "aws_ssm_parameter", ID: "simple-name"}, "simple-name"}, // no Config -> fall back to ID
	}
	for _, c := range cases {
		if got := importID(c.r); got != c.want {
			t.Errorf("importID(%s) = %q, want %q", c.r.TFType, got, c.want)
		}
	}
}
