package awsx

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Service clients must use the shared HTTP client as-is. If the SDK wraps
// or clones it (as it does a BuildableClient), every client gets its own
// connection pool again and every call pays a fresh TCP + TLS handshake.
func TestSharedHTTPClientIsNotCloned(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1", HTTPClient: sharedHTTPClient()}
	a := sts.NewFromConfig(cfg).Options().HTTPClient
	b := sts.NewFromConfig(cfg).Options().HTTPClient
	if a != cfg.HTTPClient || b != cfg.HTTPClient {
		t.Fatalf("service clients got their own HTTP client (%p, %p), not the shared one (%p)", a, b, cfg.HTTPClient)
	}
}
