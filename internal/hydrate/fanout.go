package hydrate

import (
	"context"
	"sync"

	"github.com/virtualbeck/inherit/internal/par"
	"github.com/virtualbeck/inherit/model"
)

// Fanout expands one discovered resource into extra standalone resources, for
// cases the provider models as separate types (security-group rules, S3 bucket
// sub-configs, ...). It runs after the parent is hydrated and only sees parents
// that hydrated cleanly.
type Fanout func(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error)

var fanoutRegistry = map[string]Fanout{}

func registerFanout(parentTFType string, f Fanout) {
	if _, dup := fanoutRegistry[parentTFType]; dup {
		panic("hydrate: duplicate fanout for " + parentTFType)
	}
	fanoutRegistry[parentTFType] = f
}

// runFanout appends child resources produced from already-hydrated parents.
func runFanout(ctx context.Context, c *Clients, inv *model.Inventory, concurrency int) []error {
	if concurrency <= 0 {
		concurrency = 16
	}
	var parents []model.Resource
	for _, r := range inv.Resources {
		if r.Config == nil {
			continue
		}
		if _, ok := fanoutRegistry[r.TFType]; ok {
			parents = append(parents, r)
		}
	}

	var (
		mu       sync.Mutex
		children []model.Resource
		errs     []error
	)
	par.Each(parents, concurrency, func(r model.Resource) {
		kids, err := fanoutRegistry[r.TFType](ctx, c, r)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		children = append(children, kids...)
	})
	inv.Resources = append(inv.Resources, children...)
	return errs
}
