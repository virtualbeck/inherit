package cli

import (
	"github.com/virtualbeck/inherit/internal/hydrate"
	"github.com/virtualbeck/inherit/model"
)

const coverageFile = "coverage.json"

// coverage holds type names and counts only, never ARNs, IDs or error text, so reports from many accounts can be pooled and kept.
type coverage struct {
	ToolVersion     string         `json:"tool_version"`
	Account         string         `json:"account"`
	Regions         int            `json:"regions"`
	Hydrated        int            `json:"hydrated"`
	HydratedByType  map[string]int `json:"hydrated_by_type"`
	NoHydrator      map[string]int `json:"no_hydrator"`
	Unmapped        map[string]int `json:"unmapped"`
	HydrationErrors map[string]int `json:"hydration_errors"`
	Skipped         map[string]int `json:"skipped"`
	Baseline        map[string]int `json:"baseline"`
	OtherErrors     int            `json:"other_errors"`
}

func coverageReport(inv model.Inventory, st hydrate.Stats) coverage {
	byType, baseline := map[string]int{}, map[string]int{}
	for _, r := range inv.Resources {
		if r.Config != nil && r.TFType != "" {
			byType[r.TFType]++
		}
		if r.Baseline != "" {
			baseline[r.TFType]++
		}
	}
	typed := 0
	for _, n := range st.ErrorsByType {
		typed += n
	}
	return coverage{
		ToolVersion:     inv.ToolVersion,
		Account:         inv.Account,
		Regions:         len(inv.Regions),
		Hydrated:        st.Hydrated,
		HydratedByType:  byType,
		NoHydrator:      st.NoHydrator,
		Unmapped:        st.Unmapped,
		HydrationErrors: st.ErrorsByType,
		Skipped:         st.Skipped,
		Baseline:        baseline,
		OtherErrors:     len(st.Errors) - typed,
	}
}
