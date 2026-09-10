package awsx

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnabledRegions returns the regions enabled for the account, sorted. It uses
// ec2:DescribeRegions (available to essentially every principal); regions that
// are disabled for the account are excluded.
func EnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
		Filters: []ec2types.Filter{
			{Name: aws.String("opt-in-status"), Values: []string{"opt-in-not-required", "opted-in"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ec2:DescribeRegions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	sort.Strings(regions)
	if len(regions) == 0 {
		return nil, fmt.Errorf("no enabled regions returned")
	}
	return regions, nil
}
