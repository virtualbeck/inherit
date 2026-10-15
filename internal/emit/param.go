package emit

import (
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/virtualbeck/inherit/model"
)

// dataUse records which shared data sources the generated project references.
// aws_region needs one instance per region actually parameterized in this
// module: the module-default "current" instance implicitly uses the module's
// default (unaliased) provider, which is wrong for a resource pinned to an
// aliased provider -- so each non-default region gets its own aws_region
// data source, itself pinned to that same alias (see regionAliases).
type dataUse struct {
	region        bool
	regionAliases map[string]bool // region alias -> used
	account       bool
	part          bool
}

func (d *dataUse) any() bool { return d.region || len(d.regionAliases) > 0 || d.account || d.part }

// tmpl is a config value rendered as a quoted HCL template: a sequence of
// literal string parts and traversals, e.g. "arn:" + data.aws_partition... + ":...".
type tmpl struct{ parts []any } // each part is string or hcl.Traversal

// travData builds a `data.<name>.<instance>.<attr>` traversal. instance is
// "current" for the module-default data source, or a region alias for one
// pinned to that aliased provider (see dataUse.regionAliases).
func travData(name, instance, attr string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "data"},
		hcl.TraverseAttr{Name: name},
		hcl.TraverseAttr{Name: instance},
		hcl.TraverseAttr{Name: attr},
	}
}

// arnLike matches strings we are willing to rewrite: ARNs and *.amazonaws.com
// endpoints. Random values that merely contain the account number are left alone.
var arnLike = regexp.MustCompile(`^arn:|\.amazonaws\.com`)

var arnPartition = regexp.MustCompile(`^arn:(aws[a-z-]*):`)

// parameterize walks a (post-ref-substitution) config value and swaps the
// account id, the resource's own region, and the partition inside ARN-like
// strings for the matching data-source interpolation. defRegion is the
// module's default (unaliased) provider region, needed to pick the right
// aws_region data-source instance for a resource pinned to an aliased one.
func parameterize(v any, r model.Resource, defRegion string, use *dataUse) any {
	switch t := v.(type) {
	case ref, tmpl:
		return t
	case string:
		return paramString(t, r, defRegion, use)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = parameterize(e, r, defRegion, use)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, e := range t {
			s[i] = parameterize(e, r, defRegion, use)
		}
		return s
	default:
		return v
	}
}

// paramString returns the original string, or a tmpl when it substituted at
// least one of partition / region / account.
func paramString(s string, r model.Resource, defRegion string, use *dataUse) any {
	if !arnLike.MatchString(s) {
		return s
	}
	parts := []any{s}

	if m := arnPartition.FindStringSubmatch(s); m != nil {
		var ok bool
		parts, ok = replacePart(parts, "arn:"+m[1]+":", travData("aws_partition", "current", "partition"))
		use.part = use.part || ok
	}
	if r.Region != "" {
		instance := "current"
		if r.Region != defRegion {
			// this resource lives under an aliased (non-default) provider;
			// data.aws_region.current would resolve via the module's
			// default provider and interpolate the wrong region entirely.
			instance = sanitizeName(r.Region)
		}
		var ok bool
		parts, ok = replacePart(parts, ":"+r.Region+":", travData("aws_region", instance, "region"))
		if ok {
			if instance == "current" {
				use.region = true
			} else {
				if use.regionAliases == nil {
					use.regionAliases = map[string]bool{}
				}
				use.regionAliases[instance] = true
			}
		}
	}
	if r.Account != "" {
		var ok bool
		parts, ok = replacePart(parts, ":"+r.Account+":", travData("aws_caller_identity", "current", "account_id"))
		use.account = use.account || ok
	}

	if len(parts) == 1 {
		if str, ok := parts[0].(string); ok {
			return str
		}
	}
	return tmpl{parts: mergeStrings(parts)}
}

// replacePart splits string parts on needle, keeping the needle's delimiter
// characters as literals and inserting trav between them. needle is either
// "arn:<p>:" or ":<x>:".
func replacePart(parts []any, needle string, trav hcl.Traversal) ([]any, bool) {
	lead, trail := ":", ":"
	if strings.HasPrefix(needle, "arn:") {
		lead = "arn:"
	}
	matched := false
	var out []any
	for _, p := range parts {
		s, ok := p.(string)
		if !ok {
			out = append(out, p)
			continue
		}
		for {
			i := strings.Index(s, needle)
			if i < 0 {
				break
			}
			matched = true
			out = append(out, s[:i]+lead, trav)
			s = trail + s[i+len(needle):]
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return mergeStrings(out), matched
}

// mergeStrings coalesces adjacent string parts.
func mergeStrings(in []any) []any {
	out := in[:0:0]
	for _, p := range in {
		if s, ok := p.(string); ok && len(out) > 0 {
			if prev, ok := out[len(out)-1].(string); ok {
				out[len(out)-1] = prev + s
				continue
			}
		}
		out = append(out, p)
	}
	return out
}
