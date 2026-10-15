package hydrate

import (
	"context"
	"fmt"
	"sync"

	"github.com/virtualbeck/inherit/internal/par"
	"github.com/virtualbeck/inherit/model"
)

// GapFiller discovers resource types the Resource Groups Tagging API does not
// return (application auto scaling targets, ...). It returns fully-formed
// resources: TFType, Config and ImportID all set.
type GapFiller func(ctx context.Context, c *Clients, region string) ([]model.Resource, error)

var gapFillers []GapFiller

// globalGapFillers are for account-global services (IAM, ...): registered
// separately from gapFillers because they must run exactly once regardless
// of how many regions are scanned, not once per (region x filler) like a
// regional gap-filler -- IAM's ListRoles/ListUsers/etc. return the same
// complete, region-agnostic list no matter which region the client is
// configured for, so running them per-region would silently duplicate
// every result N times (once per scanned region) with no de-dup anywhere
// downstream to catch it.
var globalGapFillers []GapFiller

// gapFillConcurrency bounds the (region x filler) jobs. It's higher than
// hydration's limit because the jobs are almost all different service
// endpoints in different regions, each with its own API rate limit, and
// nearly every one is a single cheap call: the run is round-trip bound.
const gapFillConcurrency = 64

func registerGapFiller(f GapFiller)       { gapFillers = append(gapFillers, f) }
func registerGlobalGapFiller(f GapFiller) { globalGapFillers = append(globalGapFillers, f) }

// runGapFillers runs every registered gap-filler across the inventory's regions
// (each global filler exactly once, using the first scanned region only to
// build a client -- the call itself is region-agnostic) and appends what they
// find. Concurrent over (region x filler), at most concurrency at a time.
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
