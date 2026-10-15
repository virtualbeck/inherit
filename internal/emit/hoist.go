package emit

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Attributes lifted into variables.tf.
var hoistAttrs = map[string]bool{
	"name":          true,
	"bucket":        true,
	"function_name": true,
	"identifier":    true,
	"alarm_name":    true,
}

var hoistListAttrs = map[string]bool{
	"aliases": true,
}

type hoistedVar struct {
	name  string
	value cty.Value
	desc  string
}

// hoist lifts knobs into variables, resolving name collisions.
func hoist(cfg map[string]any, logicalName, tfType string, taken map[string]bool) (map[string]any, []hoistedVar) {
	var vars []hoistedVar
	out := make(map[string]any, len(cfg))
	abbrev := strings.TrimPrefix(tfType, "aws_")
	for k, v := range cfg {
		// an _id suffix alone doesn't mean foreign ID
		plainLabel := isExternalRefAttr(k) && !looksLikeExternalIDValue(v)
		if !hoistAttrs[k] && !hoistListAttrs[k] && !plainLabel {
			out[k] = v
			continue
		}
		cv := scalarCty(v)
		if cv == cty.NilVal && hoistListAttrs[k] {
			cv = listOfStringCty(v)
		}
		if cv == cty.NilVal {
			out[k] = v
			continue
		}
		// main_name says nothing; prefix with the type
		vn := logicalName + "_" + k
		if logicalName == "main" || taken[vn] {
			vn = abbrev + "_" + k
		}
		for taken[vn] {
			vn = abbrev + "_" + logicalName + "_" + k
		}
		taken[vn] = true
		vars = append(vars, hoistedVar{name: vn, value: cv})
		out[k] = ref{trav: hcl.Traversal{
			hcl.TraverseRoot{Name: "var"},
			hcl.TraverseAttr{Name: vn},
		}}
	}
	return out, vars
}

// Suffixes marking references outside this scan.
var externalRefSuffixes = []string{"_ids", "_id", "_arns", "_arn"}

func isExternalRefAttr(key string) bool {
	for _, suf := range externalRefSuffixes {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
}

// Foreign references become required variables the root supplies.
func hoistExternalRefs(cfg map[string]any, m *modBuild, logicalName, cat string, _ string, rootArgs map[string]map[string]cty.Value) map[string]any {
	if cfg == nil {
		return cfg
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !isExternalRefAttr(k) {
			out[k] = v
			continue
		}
		cv, isList, ok := externalRefCty(v)
		if !ok {
			out[k] = v
			continue
		}
		out[k] = registerExternalRef(m, logicalName, cat, k, v, cv, isList, rootArgs)
	}
	return out
}

func registerExternalRef(m *modBuild, logicalName, cat, attr string, rawVal any, cv cty.Value, isList bool, rootArgs map[string]map[string]cty.Value) ref {
	vn := claimExternalRefName(m, logicalName, attr, rawVal)
	if _, exists := m.inputs[vn]; !exists {
		typLabel := "string"
		if isList {
			typLabel = "list(string)"
		}
		m.inputs[vn] = inputSpec{typ: typLabel}
		if rootArgs[cat] == nil {
			rootArgs[cat] = map[string]cty.Value{}
		}
		rootArgs[cat][vn] = cv
	}
	return ref{trav: hcl.Traversal{
		hcl.TraverseRoot{Name: "var"},
		hcl.TraverseAttr{Name: vn},
	}}
}

// Short type prefix, hyphen, 8-17 hex digits.
var awsOpaqueIDRe = regexp.MustCompile(`^(?:ami|vpc|subnet|sg|sgr|rtb|rtbassoc|igw|eigw|nat|eni|eipalloc|eipassoc|dopt|pcx|vpce|acl|nacl|vgw|cgw|vpn|tgw|tgwrtb|tgwattach|snap|vol|fs|fsmt|fsap|pl|lt|ltver|i|eic|mesh)-[0-9a-f]{8,17}$`)

func looksLikeExternalID(s string) bool {
	return awsOpaqueIDRe.MatchString(s) || strings.HasPrefix(s, "arn:aws:")
}

func looksLikeExternalIDValue(v any) bool {
	s, ok := v.(string)
	return ok && looksLikeExternalID(s)
}

// Last pass: hoist any remaining bare IDs.
func scrubExternalIDs(cfg map[string]any, m *modBuild, logicalName, cat string, rootArgs map[string]map[string]cty.Value) map[string]any {
	scrubMap(cfg, m, logicalName, cat, rootArgs)
	return cfg
}

func scrubMap(mp map[string]any, m *modBuild, logicalName, cat string, rootArgs map[string]map[string]cty.Value) {
	for k, v := range mp {
		switch x := v.(type) {
		case string:
			if looksLikeExternalID(x) {
				mp[k] = registerExternalRef(m, logicalName, cat, k, x, cty.StringVal(x), false, rootArgs)
			}
		case map[string]any:
			scrubMap(x, m, logicalName, cat, rootArgs)
		case []any:
			if cv, isList, ok := allExternalIDList(x); ok {
				mp[k] = registerExternalRef(m, logicalName, cat, k, x, cv, isList, rootArgs)
				continue
			}
			for _, e := range x {
				if em, ok := e.(map[string]any); ok {
					scrubMap(em, m, logicalName, cat, rootArgs)
				}
			}
		}
	}
}

func allExternalIDList(x []any) (cty.Value, bool, bool) {
	if len(x) == 0 {
		return cty.NilVal, false, false
	}
	vals := make([]cty.Value, 0, len(x))
	for _, e := range x {
		s, ok := e.(string)
		if !ok || !looksLikeExternalID(s) {
			return cty.NilVal, false, false
		}
		vals = append(vals, cty.StringVal(s))
	}
	return cty.ListVal(vals), true, true
}

// Mixed lists are left alone, never partially hoisted.
func externalRefCty(v any) (value cty.Value, isList bool, ok bool) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return cty.NilVal, false, false
		}
		return cty.StringVal(x), false, true
	case []any:
		vals := make([]cty.Value, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok || s == "" {
				return cty.NilVal, false, false
			}
			vals = append(vals, cty.StringVal(s))
		}
		if len(vals) == 0 {
			return cty.NilVal, false, false
		}
		return cty.ListVal(vals), true, true
	default:
		return cty.NilVal, false, false
	}
}

// Bare attribute name first; prefix on value conflicts.
func claimExternalRefName(m *modBuild, logicalName, attr string, value any) string {
	if existing, ok := m.externalRefValues[attr]; ok {
		if reflect.DeepEqual(existing, value) {
			return attr
		}
		return logicalName + "_" + attr
	}
	if _, taken := m.inputs[attr]; taken {
		return logicalName + "_" + attr
	}
	m.externalRefValues[attr] = value
	return attr
}

func scalarCty(v any) cty.Value {
	switch x := v.(type) {
	case string:
		if x == "" {
			return cty.NilVal
		}
		return cty.StringVal(x)
	case float64:
		return cty.NumberFloatVal(x)
	case bool:
		return cty.BoolVal(x)
	default:
		return cty.NilVal
	}
}

func listOfStringCty(v any) cty.Value {
	x, ok := v.([]any)
	if !ok || len(x) == 0 {
		return cty.NilVal
	}
	vals := make([]cty.Value, 0, len(x))
	for _, e := range x {
		s, ok := e.(string)
		if !ok || s == "" {
			return cty.NilVal
		}
		vals = append(vals, cty.StringVal(s))
	}
	return cty.ListVal(vals)
}
