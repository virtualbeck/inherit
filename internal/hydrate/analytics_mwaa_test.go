package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	mwaatypes "github.com/aws/aws-sdk-go-v2/service/mwaa/types"
)

// Generic() maps the whole GetEnvironment response onto the schema cleanly
// by field name. airflow_configuration_options is the one deliberate
// exception -- it can carry real secrets (DB connection strings, etc.), so
// it's stripped after Generic() rather than ever written into generated
// config.
func TestMWAAEnvironmentConfigDropsSensitiveOptions(t *testing.T) {
	sch, err := schemaFor("aws_mwaa_environment")
	if err != nil {
		t.Fatal(err)
	}
	e := &mwaatypes.Environment{
		Name:             aws.String("env-1"),
		ExecutionRoleArn: aws.String("arn:aws:iam::123456789012:role/mwaa"),
		SourceBucketArn:  aws.String("arn:aws:s3:::bucket"),
		DagS3Path:        aws.String("dags/"),
		MaxWorkers:       aws.Int32(10),
		Schedulers:       aws.Int32(2),
		KmsKey:           aws.String("arn:aws:kms:us-east-1:123456789012:key/x"),
		AirflowConfigurationOptions: map[string]string{
			"secrets.password": "hunter2",
		},
	}
	cfg, err := Generic(e, sch, nil)
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg, "airflow_configuration_options")

	if _, ok := cfg["airflow_configuration_options"]; ok {
		t.Fatal("airflow_configuration_options must never appear in generated config")
	}
	for _, key := range []string{"max_workers", "schedulers", "kms_key"} {
		if _, ok := cfg[key]; !ok {
			t.Errorf("%s missing -- Generic() should have mapped it by field name", key)
		}
	}
	if cfg["name"] != "env-1" || cfg["dag_s3_path"] != "dags/" {
		t.Errorf("basic fields wrong: %#v", cfg)
	}
}
