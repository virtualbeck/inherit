// Package prune drops discovery noise from a hydrated inventory: the
// resources AWS materializes in every region whether or not the account
// uses that region (the default VPC and its default security group, EBS
// encryption / Backup region settings and other per-region configuration
// singletons), and then any region left with nothing real in it.
//
// A default VPC that something is actually attached to is kept -- it's
// load-bearing. Everything here is off with --include-defaults.
package prune

import (
	"regexp"
	"sort"

	"github.com/virtualbeck/inherit/model"
)

// Options controls a prune pass.
type Options struct {
	// IncludeDefaults keeps every default / singleton resource and every
	// region -- a full no-op. The escape hatch for "codify everything".
	IncludeDefaults bool
	// KeepAllRegions prunes default/singleton noise but never drops a whole
	// region. Set when the user passed an explicit --regions list.
	KeepAllRegions bool
}

// Report is what a prune pass removed.
type Report struct {
	Regions    []string // regions dropped entirely (had nothing real left)
	Defaults   int      // AWS-managed default-network resources removed
	Singletons int      // per-region configuration singletons removed
}

// Empty reports whether the pass removed nothing.
func (r Report) Empty() bool {
	return len(r.Regions) == 0 && r.Defaults == 0 && r.Singletons == 0
}

var awsIDRe = regexp.MustCompile(`^(?:vpc|subnet|sg)-[0-9a-f]{8,17}$`)

// defaultNetworkTypes are the resources AWS creates in a fresh VPC / region.
var defaultNetworkTypes = map[string]bool{
	"aws_default_vpc":         true,
	"aws_default_subnet":      true,
	"aws_default_route_table": true,
	"aws_default_network_acl": true,
}

func isDefaultSG(r model.Resource) bool {
	return r.TFType == "aws_security_group" && cfgString(r.Config, "name") == "default"
}

func isSGRule(r model.Resource) bool {
	return r.TFType == "aws_vpc_security_group_ingress_rule" ||
		r.TFType == "aws_vpc_security_group_egress_rule"
}

// singletonNoise reports whether r is a per-region configuration singleton
// carrying only its default (unconfigured) value -- i.e. it exists because
// AWS always answers the API, not because anyone set anything.
func singletonNoise(r model.Resource) bool {
	switch r.TFType {
	case "aws_backup_region_settings":
		return true // opt-in/management prefs -- noise in every unused region
	case "aws_ebs_encryption_by_default":
		on, _ := r.Config["enabled"].(bool)
		return !on // enabled=true is a deliberate security posture; keep it
	case "aws_api_gateway_account":
		return cfgString(r.Config, "cloudwatch_role_arn") == ""
	}
	return false
}

// structurallyNoise reports whether r is a candidate for removal on shape
// alone, before the "is anything attached?" check. Used both to decide what
// to drop and to exclude these resources from the reference scan (a default
// route table pointing at the default VPC must not keep it alive).
func structurallyNoise(r model.Resource) bool {
	return defaultNetworkTypes[r.TFType] || isDefaultSG(r) || isSGRule(r) || singletonNoise(r)
}

// Noise removes discovery noise from inv in place and reports what went.
func Noise(inv *model.Inventory, opt Options) Report {
	if opt.IncludeDefaults {
		return Report{}
	}

	subnetIDs := map[string]bool{}
	for _, r := range inv.Resources {
		if r.TFType == "aws_subnet" {
			subnetIDs[r.ID] = true
		}
	}

	// what real resources point at: VPC ids anywhere in config, plus a flag
	// per region for "references a subnet we didn't discover" (likely a
	// default subnet -> keep that region's default VPC, conservatively).
	referencedVPC := map[string]bool{}
	unresolvedSubnetInRegion := map[string]bool{}
	for _, r := range inv.Resources {
		if structurallyNoise(r) {
			continue
		}
		walkStrings(r.Config, func(s string) {
			if !awsIDRe.MatchString(s) {
				return
			}
			switch s[0] {
			case 'v': // vpc-
				referencedVPC[s] = true
			case 's':
				if s[1] == 'u' && !subnetIDs[s] { // subnet-
					unresolvedSubnetInRegion[r.Region] = true
				}
			}
		})
	}

	vpcKept := func(id, region string) bool {
		return referencedVPC[id] || unresolvedSubnetInRegion[region]
	}

	// first pass: which default SGs are pruned, so their rules can follow.
	prunedDefaultSG := map[string]bool{}
	for _, r := range inv.Resources {
		if isDefaultSG(r) && !vpcKept(cfgString(r.Config, "vpc_id"), r.Region) {
			prunedDefaultSG[r.ID] = true
		}
	}

	var rep Report
	kept := inv.Resources[:0:0]
	for _, r := range inv.Resources {
		drop, isDefault := false, false
		switch {
		case r.TFType == "aws_default_vpc":
			drop, isDefault = !vpcKept(r.ID, r.Region), true
		case defaultNetworkTypes[r.TFType]:
			drop, isDefault = !vpcKept(cfgString(r.Config, "vpc_id"), r.Region), true
		case isDefaultSG(r):
			drop, isDefault = !vpcKept(cfgString(r.Config, "vpc_id"), r.Region), true
		case isSGRule(r):
			drop, isDefault = prunedDefaultSG[cfgString(r.Config, "security_group_id")], true
		case singletonNoise(r):
			drop = true
		}
		if !drop {
			kept = append(kept, r)
			continue
		}
		if isDefault {
			rep.Defaults++
		} else {
			rep.Singletons++
		}
	}
	inv.Resources = kept

	if !opt.KeepAllRegions {
		live := map[string]bool{}
		for _, r := range inv.Resources {
			if r.Region != "" {
				live[r.Region] = true
			}
		}
		var keptRegions []string
		for _, reg := range inv.Regions {
			if live[reg] {
				keptRegions = append(keptRegions, reg)
			} else {
				rep.Regions = append(rep.Regions, reg)
			}
		}
		inv.Regions = keptRegions
		sort.Strings(rep.Regions)
	}
	return rep
}

func cfgString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return s
}

// walkStrings calls fn for every string value anywhere in v.
func walkStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		for _, e := range x {
			walkStrings(e, fn)
		}
	case []any:
		for _, e := range x {
			walkStrings(e, fn)
		}
	}
}
