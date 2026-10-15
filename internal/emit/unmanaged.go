package emit

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/virtualbeck/inherit/internal/redact"
)

// Attributes with redacted values go under ignore_changes.
type unmanaged struct {
	addr  string
	arn   string
	attrs []string
}

// Top-level attributes holding the sentinel anywhere, sorted.
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

// Base64 placeholders fail validate; drop them from config.
func dropRedactedScalars(tfType string, cfg map[string]any) map[string]any {
	for _, k := range []string{"user_data_base64", "user_data"} {
		if k == "user_data" && tfType != "aws_launch_template" {
			continue // plain text there
		}
		if s, ok := cfg[k].(string); ok && s == redact.Sentinel {
			delete(cfg, k)
		}
	}
	return cfg
}

func writeIgnoreChanges(b *hclwrite.Body, attrs []string) {
	b.AppendNewBlock("lifecycle", nil).Body().
		SetAttributeRaw("ignore_changes", rawExprTokens("["+strings.Join(attrs, ", ")+"]"))
}

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

func unionAttrs(sets ...[]string) []string {
	seen := map[string]bool{}
	for _, s := range sets {
		for _, a := range s {
			seen[a] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}
