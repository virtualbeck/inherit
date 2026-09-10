// Package awsx wraps AWS SDK config loading, a read-only request guard, and
// account/region resolution. Nothing here mutates the target account.
package awsx

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
)

// Load builds the shared AWS config from the standard environment/SSO/profile
// chain and attaches the read-only guard to every client derived from it.
// region, if set, pins the config's default region (individual clients still
// override per-region during the sweep). profile, if set, pins which
// ~/.aws/credentials or ~/.aws/config profile to use, overriding
// AWS_PROFILE/the "default" profile the same way AWS_PROFILE would --
// config.WithSharedConfigProfile is the SDK's own documented mechanism for
// this, not a hand-rolled env var override.
func Load(ctx context.Context, region, profile string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithAPIOptions([]func(*middleware.Stack) error{readOnlyGuard}),
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}

// Identity is the resolved caller, from sts:GetCallerIdentity.
type Identity struct {
	Account   string
	ARN       string
	UserID    string
	Partition string
	Region    string // the config's resolved region
}

// ResolveIdentity calls sts:GetCallerIdentity. It is the only "who am I" check
// inherit performs and it never gates execution.
func ResolveIdentity(ctx context.Context, cfg aws.Config) (Identity, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	id := Identity{
		Account: aws.ToString(out.Account),
		ARN:     aws.ToString(out.Arn),
		UserID:  aws.ToString(out.UserId),
		Region:  cfg.Region,
	}
	if parts := strings.SplitN(id.ARN, ":", 3); len(parts) >= 2 {
		id.Partition = parts[1]
	}
	if id.Partition == "" {
		id.Partition = "aws"
	}
	return id, nil
}
