package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_vpc_ipam", genericHydrator("aws_vpc_ipam", fetchIPAM)) }

func fetchIPAM(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeIpams(ctx, &ec2.DescribeIpamsInput{IpamIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.Ipams) == 0 {
		return nil, nil
	}
	return out.Ipams[0], nil
}
