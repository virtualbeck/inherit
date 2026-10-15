// Package prune drops AWS-created defaults and empty regions.
package prune

import (
	"regexp"
	"sort"

	"github.com/virtualbeck/inherit/model"
)

type Options struct {
	// IncludeDefaults disables pruning entirely.
	IncludeDefaults bool
	// KeepAllRegions prunes resources but never whole regions.
	KeepAllRegions bool
}

type Report struct {
	Regions    []string
	Defaults   int
	Singletons int
}

func (r Report) Empty() bool {
	return len(r.Regions) == 0 && r.Defaults == 0 && r.Singletons == 0
}

var awsIDRe = regexp.MustCompile(`^(?:vpc|subnet|sg)-[0-9a-f]{8,17}$`)

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

// singletonNoise: a per-region setting still at its default.
func singletonNoise(r model.Resource) bool {
	switch r.TFType {
	case "aws_backup_region_settings":
		return true
	case "aws_ebs_encryption_by_default":
		on, _ := r.Config["enabled"].(bool)
		return !on // enabled is deliberate posture; keep it
	case "aws_api_gateway_account":
		return cfgString(r.Config, "cloudwatch_role_arn") == ""
	}
	return false
}

// structurallyNoise: removable by shape, before reference checks.
func structurallyNoise(r model.Resource) bool {
	return defaultNetworkTypes[r.TFType] || isDefaultSG(r) || isSGRule(r) || singletonNoise(r)
}

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

	// Referenced VPCs, and regions using undiscovered subnets.
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
