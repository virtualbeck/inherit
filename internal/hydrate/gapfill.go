package hydrate

import (
	"context"
	"fmt"
	"sync"

	"github.com/virtualbeck/inherit/internal/par"
	"github.com/virtualbeck/inherit/model"
)

// GapFiller finds what the Tagging API misses.
type GapFiller func(ctx context.Context, c *Clients, region string) ([]model.Resource, error)

var gapFillers []GapFiller

// Region-agnostic fillers run once, or results duplicate.
var globalGapFillers []GapFiller

// Distinct endpoints with separate rate limits.
const gapFillConcurrency = 64

func registerGapFiller(f GapFiller)       { gapFillers = append(gapFillers, f) }
func registerGlobalGapFiller(f GapFiller) { globalGapFillers = append(globalGapFillers, f) }

// Global fillers run once, using the first region.
func runGapFillers(ctx context.Context, c *Clients, inv *model.Inventory, concurrency int) []error {
	type job struct {
		region string
		f      GapFiller
	}
	var jobs []job
	for _, region := range inv.Regions {
		for _, f := range gapFillers {
			jobs = append(jobs, job{region, f})
		}
	}
	if len(inv.Regions) > 0 {
		for _, f := range globalGapFillers {
			jobs = append(jobs, job{inv.Regions[0], f})
		}
	}

	var (
		mu   sync.Mutex
		errs []error
		add  []model.Resource
	)
	par.Each(jobs, concurrency, func(j job) {
		res, err := j.f(ctx, c, j.region)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("gapfill %s: %w", j.region, err))
			return
		}
		add = append(add, res...)
	})
	inv.Resources = append(inv.Resources, add...)
	return errs
}
