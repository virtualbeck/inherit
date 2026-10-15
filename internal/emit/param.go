package emit

import (
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/virtualbeck/inherit/model"
)

// Each non-default region gets an aliased aws_region.
type dataUse struct {
	region        bool
	regionAliases map[string]bool
	account       bool
	part          bool
}

func (d *dataUse) any() bool { return d.region || len(d.regionAliases) > 0 || d.account || d.part }

// tmpl renders as a quoted template with interpolations.
type tmpl struct{ parts []any }

func travData(name, instance, attr string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "data"},
		hcl.TraverseAttr{Name: name},
		hcl.TraverseAttr{Name: instance},
		hcl.TraverseAttr{Name: attr},
	}
}

// Only ARNs and amazonaws.com endpoints are rewritten.
var arnLike = regexp.MustCompile(`^arn:|\.amazonaws\.com`)

var arnPartition = regexp.MustCompile(`^arn:(aws[a-z-]*):`)

// parameterize swaps account, region, partition for data lookups.
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
			// aliased provider: current would interpolate the wrong region
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
