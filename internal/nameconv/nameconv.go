// Package nameconv maps AWS field names to snake_case.
package nameconv

import (
	"regexp"
	"strings"
)

var (
	splitLowerUpper = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	splitAcronym    = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)

	// Compound tokens the acronym rule would mangle.
	tokenFix = strings.NewReplacer(
		"IPv6", "Ipv6", "IPv4", "Ipv4",
		"IPAddress", "IpAddress", "IPRange", "IpRange",
		"VCpu", "Vcpu", "MiB", "Mib", "GiB", "Gib",
		"MySQL", "Mysql", "MongoDb", "Mongodb", "PostgreSQL", "Postgres",
	)
)

// Snake converts an AWS field name to snake_case.
func Snake(name string) string {
	s := tokenFix.Replace(name)
	s = splitAcronym.ReplaceAllString(s, "${1}_${2}")
	s = splitLowerUpper.ReplaceAllString(s, "${1}_${2}")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "__", "_")
	return strings.ToLower(s)
}

// SnakeKeys applies Snake to every key, recursively.
func SnakeKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[Snake(k)] = SnakeKeys(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = SnakeKeys(e)
		}
		return out
	default:
		return v
	}
}
