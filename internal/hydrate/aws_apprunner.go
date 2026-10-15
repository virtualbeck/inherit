package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_apprunner_service", hydrateAppRunnerService)
	register("aws_apprunner_vpc_connector", genericHydrator("aws_apprunner_vpc_connector", fetchAppRunnerVPCConnector))
}

func fetchAppRunnerVPCConnector(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	arn := r.ARN
	out, err := apprunner.NewFromConfig(c.Cfg(r.Region)).DescribeVpcConnector(ctx, &apprunner.DescribeVpcConnectorInput{VpcConnectorArn: &arn})
	if err != nil {
		return nil, err
	}
	return out.VpcConnector, nil
}

// Generic() for most; flatten the autoscaling ARN.
func hydrateAppRunnerService(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := apprunner.NewFromConfig(c.Cfg(r.Region)).DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: &arn})
	if err != nil || out.Service == nil {
		return nil, err
	}
	sch, err := schemaFor("aws_apprunner_service")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.Service, sch, nil)
	if err != nil {
		return nil, err
	}
	if s := out.Service.AutoScalingConfigurationSummary; s != nil {
		if v := aws.ToString(s.AutoScalingConfigurationArn); v != "" {
			cfg["auto_scaling_configuration_arn"] = v
		}
	}
	return cfg, nil
}
