package hydrate

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/virtualbeck/inherit/model"
)

// hydrateRegistered must apply retypeSentinel for gap-fillers.
func TestHydrateRegisteredAppliesRetype(t *testing.T) {
	const testType = "aws_test_retype_probe"
	registry[testType] = func(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
		return map[string]any{
			retypeSentinel: "aws_test_retype_target",
			"kept":         "value",
		}, nil
	}
	t.Cleanup(func() { delete(registry, testType) })

	cfg, finalType, err := hydrateRegistered(context.Background(), nil, model.Resource{TFType: testType})
	if err != nil {
		t.Fatal(err)
	}
	if finalType != "aws_test_retype_target" {
		t.Errorf("finalType = %q, want aws_test_retype_target", finalType)
	}
	if _, ok := cfg[retypeSentinel]; ok {
		t.Error("retypeSentinel key must be removed from cfg, not just read")
	}
	if cfg["kept"] != "value" {
		t.Error("non-sentinel keys must survive unchanged")
	}
}

func TestHydrateRegisteredNoRetype(t *testing.T) {
	const testType = "aws_test_no_retype_probe"
	registry[testType] = func(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
		return map[string]any{"name": "x"}, nil
	}
	t.Cleanup(func() { delete(registry, testType) })

	_, finalType, err := hydrateRegistered(context.Background(), nil, model.Resource{TFType: testType})
	if err != nil {
		t.Fatal(err)
	}
	if finalType != testType {
		t.Errorf("finalType = %q, want unchanged %q", finalType, testType)
	}
}

func TestHydrateRegisteredUnknownType(t *testing.T) {
	_, _, err := hydrateRegistered(context.Background(), nil, model.Resource{TFType: "aws_definitely_not_registered"})
	if err == nil {
		t.Error("expected an error for an unregistered type")
	}
}

// Interrupted hydration is an error, not a smaller inventory.
func TestRunReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv := &model.Inventory{Resources: []model.Resource{{
		ARN: "arn:aws:ec2:us-east-1:1:vpc/vpc-1", Service: "ec2", Type: "vpc",
		Region: "us-east-1", ID: "vpc-1",
	}}}
	_, err := Run(ctx, aws.Config{Region: "us-east-1"}, inv, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if inv.Resources[0].Config != nil {
		t.Error("no hydrator should run after cancellation")
	}
}

// Coverage gaps are counted per type so real scans can rank what to hydrate next.
func TestRunCountsGapsPerType(t *testing.T) {
	arnToTF[[2]string{"probe", "nohyd"}] = "aws_probe_nohyd"
	arnToTF[[2]string{"probe", "err"}] = "aws_probe_err"
	registry["aws_probe_err"] = func(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
		return nil, errors.New("access denied")
	}
	t.Cleanup(func() {
		delete(arnToTF, [2]string{"probe", "nohyd"})
		delete(arnToTF, [2]string{"probe", "err"})
		delete(registry, "aws_probe_err")
	})
	inv := &model.Inventory{Resources: []model.Resource{
		{Service: "probe", Type: "nohyd", ID: "a"},
		{Service: "probe", Type: "nohyd", ID: "b"},
		{Service: "probe", Type: "err", ID: "c"},
		{Service: "zzz", Type: "thing", ID: "d"},
	}}
	st, err := Run(context.Background(), aws.Config{Region: "us-east-1"}, inv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st.NoHydrator["aws_probe_nohyd"] != 2 {
		t.Errorf("NoHydrator = %v, want aws_probe_nohyd: 2", st.NoHydrator)
	}
	if st.Unmapped["zzz.thing"] != 1 {
		t.Errorf("Unmapped = %v, want zzz.thing: 1", st.Unmapped)
	}
	if st.ErrorsByType["aws_probe_err"] != 1 {
		t.Errorf("ErrorsByType = %v, want aws_probe_err: 1", st.ErrorsByType)
	}
}
