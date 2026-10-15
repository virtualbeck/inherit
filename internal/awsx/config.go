// Package awsx wraps AWS SDK config loading, a read-only request guard, and
// account/region resolution. Nothing here mutates the target account.
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
		config.WithHTTPClient(sharedHTTPClient()),
		// A throttled call that runs out of retries is a resource silently
		// missing from the scan (most fillers skip on error), so back off
		// longer than the SDK's default 3 attempts. Reads are idempotent.
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

// retryMaxAttempts is the SDK's per-call attempt budget (default 3).
const retryMaxAttempts = 10

// sharedHTTPClient is one connection pool for every service client derived
// from the config. Left to the SDK, each NewFromConfig clones the transport
// (a fresh pool), so every call paid a new TCP + TLS handshake: several round
// trips to a distant region before the request even goes out. Frozen, so
// service clients use it as-is instead of cloning it. The read timeout is
// the SDK's own planned default (it ships disabled), so a stalled connection
// can't hang a scan.
func sharedHTTPClient() aws.HTTPClient {
	return awshttp.NewBuildableClient().
		WithTransportOptions(func(t *http.Transport) { t.MaxIdleConnsPerHost = 64 }).
		WithReadTimeout(5 * time.Minute).
		Freeze()
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
