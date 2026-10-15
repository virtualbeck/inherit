package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_vpc_endpoint_service", hydrateVPCEndpointService) }

func hydrateVPCEndpointService(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := ec2.NewFromConfig(c.Cfg(r.Region))
	id := r.ID
	out, err := cl.DescribeVpcEndpointServiceConfigurations(ctx, &ec2.DescribeVpcEndpointServiceConfigurationsInput{ServiceIds: []string{id}})
	if err != nil || len(out.ServiceConfigurations) == 0 {
		return nil, err
	}
	sch, err := schemaFor("aws_vpc_endpoint_service")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.ServiceConfigurations[0], sch, nil)
	if err != nil {
		return nil, err
	}
	// flatten region structs to strings
	if len(out.ServiceConfigurations[0].SupportedRegions) > 0 {
		var regions []any
		for _, sr := range out.ServiceConfigurations[0].SupportedRegions {
			if v := aws.ToString(sr.Region); v != "" {
				regions = append(regions, v)
			}
		}
		if len(regions) > 0 {
			cfg["supported_regions"] = regions
		} else {
			delete(cfg, "supported_regions")
		}
	}

	var principals []any
	token := (*string)(nil)
	for {
		perm, perr := cl.DescribeVpcEndpointServicePermissions(ctx, &ec2.DescribeVpcEndpointServicePermissionsInput{ServiceId: &id, NextToken: token})
		if perr != nil {
			break
		}
		for _, p := range perm.AllowedPrincipals {
			if v := aws.ToString(p.Principal); v != "" {
				principals = append(principals, v)
			}
		}
		if perm.NextToken == nil {
			break
		}
		token = perm.NextToken
	}
	if len(principals) > 0 {
		cfg["allowed_principals"] = principals
	}

	return cfg, nil
}
