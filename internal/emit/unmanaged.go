package emit

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/virtualbeck/inherit/internal/redact"
)

// unmanaged is one resource whose config carried redacted values (see
// internal/redact): the top-level attributes involved are written under
// lifecycle.ignore_changes so the project plans clean on day one without the
// secret ever landing in a .tf file.
type unmanaged struct {
	addr  string // module-qualified resource address
	arn   string
	attrs []string
}

// unmanagedAttrs returns, sorted, every top-level attribute of cfg that holds
// redact.Sentinel anywhere beneath it -- as a value, or as a map key (an
// access key ID used as a tag key is renamed to Sentinel + "_key_N").
func unmanagedAttrs(cfg map[string]any) []string {
	var out []string
	for k, v := range cfg {
		if hasSentinel(v) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func hasSentinel(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.HasPrefix(t, redact.Sentinel)
	case map[string]any:
		for k, e := range t {
			if strings.HasPrefix(k, redact.Sentinel) || hasSentinel(e) {
				return true
			}
		}
	case map[string]string:
		for k, e := range t {
			if strings.HasPrefix(k, redact.Sentinel) || strings.HasPrefix(e, redact.Sentinel) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(t, hasSentinel) {
			return true
		}
	}
	return false
}

// dropRedactedScalars removes top-level attributes whose whole value is the
// sentinel when the provider format-checks them (base64 user data): a
// placeholder there fails validate, and with the attribute under
// ignore_changes, leaving it out of config plans exactly the same. Other
// placeholders stay -- some are required in practice (aws_ssm_parameter
// needs exactly one of value/insecure_value), and in place they point at
// what to fill in.
func dropRedactedScalars(tfType string, cfg map[string]any) map[string]any {
	for _, k := range []string{"user_data_base64", "user_data"} {
		if k == "user_data" && tfType != "aws_launch_template" {
			continue // aws_instance.user_data is plain text
		}
		if s, ok := cfg[k].(string); ok && s == redact.Sentinel {
			delete(cfg, k)
		}
	}
	return cfg
}

// writeIgnoreChanges appends lifecycle { ignore_changes = [attrs...] }.
func writeIgnoreChanges(b *hclwrite.Body, attrs []string) {
	b.AppendNewBlock("lifecycle", nil).Body().
		SetAttributeRaw("ignore_changes", rawExprTokens("["+strings.Join(attrs, ", ")+"]"))
}

// unmanagedDoc is UNMANAGED_FIELDS.md: every attribute left to
// ignore_changes, and where its real value is.
func unmanagedDoc(list []unmanaged) string {
	var b strings.Builder
	b.WriteString("# Unmanaged fields\n\n")
	b.WriteString("These attributes routinely hold secrets (Lambda environment variables, EC2\n")
	b.WriteString("user data, plain SSM parameter values, access key IDs, ...). inherit kept their\n")
	b.WriteString("real values out of every `.tf` file: each one is listed under its resource's\n")
	b.WriteString("`lifecycle { ignore_changes = [...] }`, so the project plans clean as-is and\n")
	b.WriteString("Terraform will not touch them.\n\n")
	b.WriteString("The real values are in `inventory.secrets.json` (gitignored, never commit it),\n")
	b.WriteString("keyed by `resource_arn` and `path`. To bring a field under management, wire it\n")
	b.WriteString("up from a secret store or a `sensitive` variable, then remove it from\n")
	b.WriteString("`ignore_changes`.\n\n")
	b.WriteString("| Resource | Attributes | ARN |\n|---|---|---|\n")
	for _, u := range list {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` |\n", u.addr, "`"+strings.Join(u.attrs, "`, `")+"`", u.arn)
	}
	return b.String()
}

// unionAttrs merges attribute lists, sorted and deduplicated.
func unionAttrs(sets ...[]string) []string {
	seen := map[string]bool{}
	for _, s := range sets {
		for _, a := range s {
			seen[a] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}
