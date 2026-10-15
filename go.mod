module github.com/virtualbeck/inherit

go 1.27.0

toolchain go1.27.2

require (
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.57.4
	github.com/aws/aws-sdk-go-v2/service/acm v1.50.4
	github.com/aws/aws-sdk-go-v2/service/amp v1.54.5
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.52.1
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.46.1
	github.com/aws/aws-sdk-go-v2/service/appconfig v1.54.4
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.51.4
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.48.4
	github.com/aws/aws-sdk-go-v2/service/appsync v1.62.4
	github.com/aws/aws-sdk-go-v2/service/athena v1.66.4
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.78.4
	github.com/aws/aws-sdk-go-v2/service/backup v1.69.1
	github.com/aws/aws-sdk-go-v2/service/batch v1.78.3
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.82.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.73.3
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.89.3
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.78.4
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.55.4
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.42.4
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.75.3
	github.com/aws/aws-sdk-go-v2/service/configservice v1.74.4
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.75.1
	github.com/aws/aws-sdk-go-v2/service/datasync v1.68.0
	github.com/aws/aws-sdk-go-v2/service/directconnect v1.55.1
	github.com/aws/aws-sdk-go-v2/service/dlm v1.45.4
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.70.3
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.339.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.4
	github.com/aws/aws-sdk-go-v2/service/ecs v1.100.3
	github.com/aws/aws-sdk-go-v2/service/efs v1.49.4
	github.com/aws/aws-sdk-go-v2/service/eks v1.104.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.63.3
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.43.4
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.4
	github.com/aws/aws-sdk-go-v2/service/emr v1.70.4
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.3
	github.com/aws/aws-sdk-go-v2/service/firehose v1.52.4
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.45.3
	github.com/aws/aws-sdk-go-v2/service/glue v1.171.0
	github.com/aws/aws-sdk-go-v2/service/grafana v1.44.4
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.100.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.4
	github.com/aws/aws-sdk-go-v2/service/kafka v1.65.4
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.56.4
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.4
	github.com/aws/aws-sdk-go-v2/service/lambda v1.113.0
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.42.4
	github.com/aws/aws-sdk-go-v2/service/mq v1.45.4
	github.com/aws/aws-sdk-go-v2/service/mwaa v1.48.4
	github.com/aws/aws-sdk-go-v2/service/neptune v1.53.4
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.76.1
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.85.1
	github.com/aws/aws-sdk-go-v2/service/organizations v1.62.0
	github.com/aws/aws-sdk-go-v2/service/pipes v1.32.4
	github.com/aws/aws-sdk-go-v2/service/ram v1.45.4
	github.com/aws/aws-sdk-go-v2/service/rds v1.130.3
	github.com/aws/aws-sdk-go-v2/service/redshift v1.71.4
	github.com/aws/aws-sdk-go-v2/service/resourceexplorer2 v1.33.4
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.41.4
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.4
	github.com/aws/aws-sdk-go-v2/service/route53resolver v1.54.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.3
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.284.0
	github.com/aws/aws-sdk-go-v2/service/scheduler v1.25.4
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.4
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.85.0
	github.com/aws/aws-sdk-go-v2/service/servicediscovery v1.49.4
	github.com/aws/aws-sdk-go-v2/service/ses v1.42.4
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.79.1
	github.com/aws/aws-sdk-go-v2/service/sfn v1.51.4
	github.com/aws/aws-sdk-go-v2/service/signer v1.41.4
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.5
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.4
	github.com/aws/aws-sdk-go-v2/service/ssm v1.79.3
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4
	github.com/aws/aws-sdk-go-v2/service/transfer v1.86.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.83.4
	github.com/aws/smithy-go v1.28.5
	github.com/hashicorp/hcl/v2 v2.25.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/zclconf/go-cty v1.19.0
)

require (
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/apparentlymart/go-textseg/v17 v17.0.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)
