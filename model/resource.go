// Package model holds the inventory data types.
package model

import (
	"sort"
	"strings"
)

// Resource is one discovered AWS resource.
type Resource struct {
	ARN     string            `json:"arn"`
	Service string            `json:"service"`           // e.g. "s3", "ec2"
	Type    string            `json:"type"`              // resource-type segment of the ARN
	TFType  string            `json:"tf_type,omitempty"` // e.g. "aws_vpc", once resolved
	Region  string            `json:"region"`            // "" for global services
	Account string            `json:"account"`
	ID      string            `json:"id"` // resource identifier segment of the ARN
	Tags    map[string]string `json:"tags,omitempty"`
	Config  map[string]any    `json:"config,omitempty"` // TF-attribute-shaped, filled by hydration

	// ImportID overrides ID in import blocks when needed.
	ImportID string `json:"import_id,omitempty"`
}

type Inventory struct {
	// ToolVersion is the inherit version that wrote this.
	ToolVersion string     `json:"tool_version"`
	Account     string     `json:"account"`
	Partition   string     `json:"partition"`
	Regions     []string   `json:"regions"`
	Resources   []Resource `json:"resources"`
}

// CountsByType counts resources by service.type.
func (inv Inventory) CountsByType() map[string]int {
	m := map[string]int{}
	for _, r := range inv.Resources {
		k := r.Service + "." + r.Type
		if r.Type == "" {
			k = r.Service
		}
		m[k]++
	}
	return m
}

// SortedTypeCounts sorts CountsByType by count, then name.
func (inv Inventory) SortedTypeCounts() []TypeCount {
	m := inv.CountsByType()
	out := make([]TypeCount, 0, len(m))
	for k, v := range m {
		out = append(out, TypeCount{Type: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// TypeCount is one row of the discovery summary.
type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// ParseARN splits an ARN into its parts.
func ParseARN(arn string) (partition, service, region, account, resource string, ok bool) {
	// arn:partition:service:region:account-id:resource
	p := strings.SplitN(arn, ":", 6)
	if len(p) < 6 || p[0] != "arn" {
		return "", "", "", "", "", false
	}
	return p[1], p[2], p[3], p[4], p[5], true
}

// SplitResource splits a resource segment into type, id.
func SplitResource(resource string) (rtype, id string) {
	if i := strings.IndexAny(resource, "/:"); i >= 0 {
		return resource[:i], resource[i+1:]
	}
	return "", resource
}
