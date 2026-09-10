// Package nameconv converts AWS API field names (PascalCase, acronym-heavy) to
// Terraform attribute names (snake_case). It is deliberately generic: the
// result is always filtered against the real provider schema, and per-resource
// overrides handle the handful of names the mechanical rule gets wrong.
package nameconv

import (
	"regexp"
	"strings"
)

var (
	splitLowerUpper = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	splitAcronym    = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)

	// compound tokens the acronym rule would mangle (IPv6 -> i_pv6).
	// VCpu/MiB/GiB found via aws_ecs_capacity_provider's
	// managed_instances_provider.instance_requirements (VCpuCount ->
	// v_cpu_count, MemoryMiB -> memory_mi_b, AcceleratorTotalMemoryMiB,
	// MemoryGiBPerVCpu -- all the same single-trailing-capital pattern as
	// IPv4/IPv6, just not caught until a field name actually used it).
	// MySQL/MongoDb found via aws_dms_endpoint's engine-specific settings
	// blocks (MySQLSettings -> my_sql_settings instead of mysql_settings,
	// MongoDbSettings -> mongo_db_settings instead of mongodb_settings) --
	// same mechanical-rule-mangles-a-compound-word class as IPv4/IPv6/VCpu
	// above. PostgreSQL is a different kind of fix (Postgres is a genuine
	// abbreviation the schema chose, not a mechanically-derivable
	// snake-casing of "PostgreSQL" no matter how the acronym rule is
	// tuned) but fits the same replace-before-splitting mechanism.
	tokenFix = strings.NewReplacer(
		"IPv6", "Ipv6", "IPv4", "Ipv4",
		"IPAddress", "IpAddress", "IPRange", "IpRange",
		"VCpu", "Vcpu", "MiB", "Mib", "GiB", "Gib",
		"MySQL", "Mysql", "MongoDb", "Mongodb", "PostgreSQL", "Postgres",
	)
)

// Snake converts a single AWS field name to snake_case.
//
//	VpcId                  -> vpc_id
//	CidrBlock              -> cidr_block
//	ARN                    -> arn
//	KmsKeyId               -> kms_key_id
//	DBInstanceIdentifier   -> db_instance_identifier
//	IPv6CidrBlock          -> ipv6_cidr_block
func Snake(name string) string {
	s := tokenFix.Replace(name)
	s = splitAcronym.ReplaceAllString(s, "${1}_${2}")
	s = splitLowerUpper.ReplaceAllString(s, "${1}_${2}")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "__", "_")
	return strings.ToLower(s)
}

// SnakeKeys walks a decoded JSON value (from json.Unmarshal into any) and
// returns a copy with every map key converted with Snake. Slices and nested
// maps are handled recursively. Used to turn a marshalled SDK response into a
// Terraform-shaped map before it is filtered against the schema.
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
