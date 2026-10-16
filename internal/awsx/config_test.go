package awsx

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// A cloned client means a fresh pool.
func TestSharedHTTPClientIsNotCloned(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1", HTTPClient: sharedHTTPClient()}
	a := sts.NewFromConfig(cfg).Options().HTTPClient
	b := sts.NewFromConfig(cfg).Options().HTTPClient
	if a != cfg.HTTPClient || b != cfg.HTTPClient {
		t.Fatalf("service clients got their own HTTP client (%p, %p), not the shared one (%p)", a, b, cfg.HTTPClient)
	}
}

// No region anywhere still loads a usable config.
func TestLoadFallsBackToARegion(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)

	cfg, err := Load(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Region != fallbackRegion {
		t.Errorf("region = %q, want %q", cfg.Region, fallbackRegion)
	}
	cfg, err = Load(context.Background(), "eu-west-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("explicit region lost: %q", cfg.Region)
	}
}
