package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() { registerGapFiller(gapFillEBSDefaults) }

// gapFillEBSDefaults discovers the region's EBS-encryption-by-default
// settings -- true account/region singletons (GetEbsEncryptionByDefault/
// GetEbsDefaultKmsKeyId take no input), no ARN or tagging concept at all.
func gapFillEBSDefaults(ctx context.Context, c *Clients, region string) ([]model.Resource, error) {
	cl := ec2.NewFromConfig(c.Cfg(region))
	var out []model.Resource

	if enc, err := cl.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{}); err == nil {
		out = append(out, model.Resource{
			Service: "ec2", Type: "ebs-encryption-by-default", TFType: "aws_ebs_encryption_by_default",
			Region: region, ID: region, ImportID: region,
			Config: map[string]any{"enabled": aws.ToBool(enc.EbsEncryptionByDefault)},
		})
	}

	if key, err := cl.GetEbsDefaultKmsKeyId(ctx, &ec2.GetEbsDefaultKmsKeyIdInput{}); err == nil {
		// GetEbsDefaultKmsKeyId returns the literal alias "alias/aws/ebs"
		// (not an ARN) when the account is still on the AWS-managed default
		// -- key_arn is Required+ARN-validated, so only emit this when a
		// real customer key has actually been set as the default.
		if arn := aws.ToString(key.KmsKeyId); strings.HasPrefix(arn, "arn:") {
			out = append(out, model.Resource{
				Service: "ec2", Type: "ebs-default-kms-key", TFType: "aws_ebs_default_kms_key",
				Region: region, ID: region, ImportID: region,
				Config: map[string]any{"key_arn": arn},
			})
		}
	}

	return out, nil
}
