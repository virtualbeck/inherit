// Package awsx: AWS config behind a read-only guard.
package awsx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
)

// Load builds the shared, read-only-guarded AWS config.
func Load(ctx context.Context, region, profile string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithAPIOptions([]func(*middleware.Stack) error{readOnlyGuard}),
		config.WithHTTPClient(sharedHTTPClient()),
		// Exhausted retries silently drop resources; retry longer.
		config.WithRetryMaxAttempts(retryMaxAttempts),
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

const retryMaxAttempts = 10

// One shared pool; the SDK clones per client.
func sharedHTTPClient() aws.HTTPClient {
	return awshttp.NewBuildableClient().
		WithTransportOptions(func(t *http.Transport) { t.MaxIdleConnsPerHost = 64 }).
		WithReadTimeout(5 * time.Minute).
		Freeze()
}

type Identity struct {
	Account   string
	ARN       string
	UserID    string
	Partition string
	Region    string
}

// ResolveIdentity calls sts:GetCallerIdentity; it never gates.
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
