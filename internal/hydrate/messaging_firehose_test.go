package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
)

// TestFirehoseS3Config guards the Required s3_configuration block that
// redshift/elasticsearch/http_endpoint/splunk destinations all need (min
// items 1 in the schema) but which the hydrator used to never populate at
// all for anything but extended_s3.
func TestFirehoseS3Config(t *testing.T) {
	if got := firehoseS3Config(nil); got != nil {
		t.Errorf("firehoseS3Config(nil) = %v, want nil", got)
	}
	s := &fhtypes.S3DestinationDescription{
		BucketARN: aws.String("arn:aws:s3:::my-bucket"),
		RoleARN:   aws.String("arn:aws:iam::123456789012:role/firehose"),
		Prefix:    aws.String("data/"),
		BufferingHints: &fhtypes.BufferingHints{
			SizeInMBs:         aws.Int32(5),
			IntervalInSeconds: aws.Int32(300),
		},
	}
	got := firehoseS3Config(s)
	want := map[string]any{
		"bucket_arn":         "arn:aws:s3:::my-bucket",
		"role_arn":           "arn:aws:iam::123456789012:role/firehose",
		"prefix":             "data/",
		"buffering_size":     int32(5),
		"buffering_interval": int32(300),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("firehoseS3Config()[%q] = %v, want %v", k, got[k], v)
		}
	}
}
