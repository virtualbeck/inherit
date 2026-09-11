package hydrate

import (
	"context"
	"sync"

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
	type job struct{ r model.Resource }
	var jobs []job
	for _, r := range inv.Resources {
		if r.Config == nil {
			continue
		}
		if _, ok := fanoutRegistry[r.TFType]; ok {
			jobs = append(jobs, job{r})
		}
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, concurrency)
		children []model.Resource
		errs     []error
	)
	for _, j := range jobs {
		j := j
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			kids, err := fanoutRegistry[j.r.TFType](ctx, c, j.r)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			children = append(children, kids...)
		}()
	}
	wg.Wait()
	inv.Resources = append(inv.Resources, children...)
	return errs
}
