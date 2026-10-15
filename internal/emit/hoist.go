package emit

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// hoistAttrs are the per-resource "knobs" worth lifting into variables.tf so a
// consumer can retarget the project without editing main.tf. Kept deliberately
// small: the resource's primary name/identifier only.
var hoistAttrs = map[string]bool{
	"name":          true,
	"bucket":        true,
	"function_name": true,
	"identifier":    true,
	"alarm_name":    true,
}

// hoistListAttrs are hoistAttrs' list(string) counterpart -- attributes
// that are a genuine per-deployment knob (confirmed against a real
// account: aws_cloudfront_distribution.aliases, the distribution's custom
// domain names -- exactly the kind of thing a consumer retargeting the
// project needs to change, the same reasoning as "name"/"bucket", just
// list-shaped instead of scalar).
var hoistListAttrs = map[string]bool{
	"aliases": true,
}

type hoistedVar struct {
	name  string
	value cty.Value
	desc  string
}

// hoist lifts allowlisted top-level scalar attributes of one resource into
// variables, replacing the literal with a var.<name> reference. `taken` is
// the module's set of already-claimed variable names -- hoist adds to it and
// resolves collisions, which happen when two resources of different types
// share a logical name (e.g. both are the sole one of their type -> `main`).
// No description: a variable named e.g. "web_name" with its discovered value
// as the visible default already says what it's for.
func hoist(cfg map[string]any, logicalName, tfType string, taken map[string]bool) (map[string]any, []hoistedVar) {
	var vars []hoistedVar
	out := make(map[string]any, len(cfg))
	abbrev := strings.TrimPrefix(tfType, "aws_")
	for k, v := range cfg {
		// isExternalRefAttr(k) alone (an "_id"/"_arn"-suffixed name) isn't
		// enough to know this is really a foreign AWS resource reference --
		// confirmed against a real account: aws_cloudwatch_event_target's
		// target_id is a free-text label ("AuditManagerTarget"), not an
		// opaque id, but the name suffix alone sent it through
		// hoistExternalRefs as a required no-default root variable, the same
		// treatment a genuine foreign vpc_id gets. A value that doesn't
		// actually look like an AWS id/ARN gets the ordinary defaulted
		// treatment here instead (like "name"); hoistExternalRefs (which
		// runs right after this) only ever sees what's left, so a value
		// that DOES look external still gets pushed to the root exactly as
		// before.
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
		// "main_name" carries no information, and any shared logical name is
		// ambiguous once two types use it. Prefer the type: "iam_policy_name".
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

// externalRefSuffixes mark an attribute as a likely reference to a resource
// outside this scan's discovered set: wireValue already turned any in-scope
// match (a literal equal to a sibling resource's bare id/ARN) into a real
// cross-resource reference, so whatever survives as a bare literal under one
// of these names is a foreign key inherit couldn't resolve on its own --
// e.g. a security group's vpc_id when that VPC wasn't part of this scan.
var externalRefSuffixes = []string{"_ids", "_id", "_arns", "_arn"}

func isExternalRefAttr(key string) bool {
	for _, suf := range externalRefSuffixes {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
}

// hoistExternalRefs replaces top-level attributes matching
// externalRefSuffixes with a required (no-default) module variable,
// recording the literal for the root's module call to supply explicitly --
// so the one place account/environment-specific wiring lives is the root
// main.tf, and the module's own implementation stays reusable as-is (the
// same property --environment leans on: independently-generated modules
// that still follow one convention). Multiple resources needing the SAME
// value for the SAME attribute name share one bare-named variable (e.g.
// var.vpc_id, not sg_x_vpc_id and sg_y_vpc_id both defaulting to the same
// literal); a genuine conflict -- same name, different value -- falls back
// to a per-resource-prefixed name instead of silently colliding. No
// description: a variable named "vpc_id" (or, on conflict, "other_vpc_id")
// is already self-explanatory -- restating "this is a reference outside
// this scan" every time adds nothing a careful reader doesn't already see.
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

// registerExternalRef claims a module variable for one external reference
// value, records the root main.tf argument that supplies it, and returns the
// var.<name> reference to substitute for the literal.
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

// awsOpaqueIDRe matches AWS's system-assigned resource ids: a short type
// prefix, a hyphen, then 8-17 hex digits (legacy 8, long-format 17, a few
// services in between). The prefix list is specific enough that a human name
// like "prod-12345678" won't match.
var awsOpaqueIDRe = regexp.MustCompile(`^(?:ami|vpc|subnet|sg|sgr|rtb|rtbassoc|igw|eigw|nat|eni|eipalloc|eipassoc|dopt|pcx|vpce|acl|nacl|vgw|cgw|vpn|tgw|tgwrtb|tgwattach|snap|vol|fs|fsmt|fsap|pl|lt|ltver|i|eic|mesh)-[0-9a-f]{8,17}$`)

func looksLikeExternalID(s string) bool {
	return awsOpaqueIDRe.MatchString(s) || strings.HasPrefix(s, "arn:aws:")
}

// looksLikeExternalIDValue is looksLikeExternalID for a config value of
// unknown shape (only a bare string can look like one; anything else --
// including the empty string -- is not, and is left for scalarCty's own
// guard to skip regardless).
func looksLikeExternalIDValue(v any) bool {
	s, ok := v.(string)
	return ok && looksLikeExternalID(s)
}

// scrubExternalIDs is the last emit pass over a resource's config: after
// wireValue turned in-scope id/arn literals into cross-references and
// hoistExternalRefs lifted the obvious top-level *_id / *_arn attributes,
// anything still a bare AWS id or ARN literal -- at ANY depth, and regardless
// of its attribute name -- is a reference to something outside this scan that
// inherit couldn't resolve. Each is hoisted to a module variable (the literal
// becomes its default in variables.tf) so no opaque id ever appears in a
// resource body; the wiring lives in variables.tf + the root main.tf.
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

// allExternalIDList reports whether every element of x is a bare AWS-id/ARN
// string (in which case the whole list is hoisted as one list(string) var).
// A mixed list -- some already a resolved reference, some not -- is left for
// per-element recursion.
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

// externalRefCty converts a still-literal string or list-of-strings value
// (anything else -- a ref/tmpl wireValue already resolved, a bool, a
// number -- isn't a candidate) into its cty form, reporting whether it's a
// list. A list with even one non-string or empty element is left alone
// entirely rather than partially hoisted (rare: some elements already
// resolved to an in-scope reference, some didn't -- not worth the awkward
// generated HCL a partial hoist would need).
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

// claimExternalRefName tries the bare attribute name first (e.g. "vpc_id"),
// shared across every resource in this module that needs the same value; a
// resource needing a DIFFERENT value under the same name gets its own
// per-resource-prefixed variable instead of silently colliding with someone
// else's.
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

// listOfStringCty is scalarCty for hoistListAttrs: v must be a non-empty
// []any of non-empty strings, or NilVal (never a partial hoist -- a list
// with anything else in it isn't the simple "list of knobs" shape this is
// for).
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
