package hydrate

import (
	"context"
	"testing"

	"github.com/virtualbeck/inherit-core/model"
)

// hydrateRegistered exists specifically for gap-fillers, which run outside
// Run()'s own per-resource loop -- the only other place retypeSentinel is
// applied. A bare registry[tfType] lookup silently leaves an unprocessed
// sentinel key sitting in cfg and never updates the resource's type (e.g.
// gapFillDefaultNetwork's aws_vpc entries would keep emitting as plain
// aws_vpc despite hydrateVPC's own retype firing correctly).
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
