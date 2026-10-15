package emit

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/virtualbeck/inherit/model"
	"github.com/zclconf/go-cty/cty"
)

// fgroup is a set of same-type, same-category resources whose configurations
// are identical except along a small number of simple scalar/list/map
// attributes -- emitted as ONE `resource` block with `for_each` over a
// `local` map instead of N near-duplicate blocks (spec §5.3). N subnets
// across AZs, N of the same SG for different CIDRs, N near-identical IAM
// policies: one block, keyed by a stable string (the AZ, the CIDR, the
// name), never subnet_1 / subnet_2 / subnet_3.
type fgroup struct {
	cat    string
	tfType string
	name   string // the shared logical name (aws_subnet.private)
	// localName is the group's `local.X` map name -- set by Write() after
	// consolidate() returns. Defaults to name, but a `locals {}` block is
	// flat and NOT type-qualified the way a resource address is: two
	// groups of DIFFERENT tf types legitimately share the same name (two
	// resource blocks named "policy" don't collide -- their types differ),
	// but if left as name, both would resolve to the same local.policy,
	// silently clobbering one group's for_each data with the other's.
	// Confirmed against a real account: aws_iam_group_policy_attachment
	// "policy", aws_iam_role_policy_attachment "policy", and
	// aws_iam_user_policy_attachment "policy" all reduced to local.policy,
	// so two of the three for_each'd over the third's data (each.value
	// referencing attributes -- group/role -- that don't exist on it),
	// deterministically failing `terraform validate`.
	localName string
	diffKeys  []string // attributes that vary across members (sorted)
	keyAttr   string   // the attribute whose value is the for_each map key ("" -> synthetic)
	memIdx    []int    // indices into the caller's items slice
	keys      []string // for_each map key per member (parallel to memIdx)
}

// consolidateKeyAttrs is the priority order for choosing which varying
// attribute supplies the for_each map key. First one that is a distinct,
// non-empty string on every member wins.
var consolidateKeyAttrs = []string{
	"availability_zone", "cidr_block", "cidr_ipv4", "cidr_ip",
	"name", "bucket", "domain_name", "identifier", "key", "path",
}

// consolidate groups items (already category-assigned and individually named)
// into for_each groups. It never merges across category, tf type, or region,
// and only merges runs of >= 3 whose configs match exactly outside a set of
// simple varying attributes. catNamers is the live per-category name registry
// -- a group claims its shared name through it so it can't collide with an
// un-consolidated resource's name.
func consolidate(items []placed, catNamers map[string]*namer) []*fgroup {
	type bucketKey struct{ cat, tfType string }
	buckets := map[bucketKey][]int{}
	for i := range items {
		bk := bucketKey{items[i].cat, items[i].r.TFType}
		buckets[bk] = append(buckets[bk], i)
	}
	order := make([]bucketKey, 0, len(buckets))
	for bk := range buckets {
		order = append(order, bk)
	}
	sort.Slice(order, func(a, b int) bool {
		if order[a].cat != order[b].cat {
			return order[a].cat < order[b].cat
		}
		return order[a].tfType < order[b].tfType
	})

	var groups []*fgroup
	for _, bk := range order {
		idxs := buckets[bk]
		if len(idxs) < 3 || freeformIDTypes[bk.tfType] {
			continue
		}
		for _, sub := range partitionConsolidatable(items, idxs) {
			if len(sub) < 3 {
				continue
			}
			if g := buildGroup(items, sub, catNamers); g != nil {
				groups = append(groups, g)
			}
		}
	}
	return groups
}

// partitionConsolidatable splits idxs (all one cat+type) into runs that are
// config-identical once the varying simple attributes are set aside. Members
// on different regions, or differing in any non-simple (nested block, wired
// reference) attribute, land in separate runs.
func partitionConsolidatable(items []placed, idxs []int) [][]int {
	present := map[string]int{}
	for _, i := range idxs {
		for k := range items[i].r.Config {
			present[k]++
		}
	}
	flex := map[string]bool{}
	for k, cnt := range present {
		if cnt != len(idxs) {
			continue // present on only some members -> a real structural difference
		}
		allSimple, differ := true, false
		var first any
		for n, i := range idxs {
			v := items[i].r.Config[k]
			// A differing bool almost always marks two genuinely different
			// configurations (public vs private subnet, enabled vs not) rather
			// than a parameterizable knob -- keep it in the signature so those
			// split into separate groups.
			if _, isBool := v.(bool); isBool || !simpleVal(v) {
				allSimple = false
				break
			}
			if n == 0 {
				first = v
			} else if !reflect.DeepEqual(v, first) {
				differ = true
			}
		}
		if allSimple && differ {
			flex[k] = true
		}
	}

	runs := map[string][]int{}
	var runOrder []string
	for _, i := range idxs {
		sig := consolidateSignature(items[i].r, flex)
		if _, ok := runs[sig]; !ok {
			runOrder = append(runOrder, sig)
		}
		runs[sig] = append(runs[sig], i)
	}
	out := make([][]int, 0, len(runOrder))
	for _, s := range runOrder {
		out = append(out, runs[s])
	}
	return out
}

// consolidateSignature is a stable string identifying a resource's config
// with the varying attributes removed, plus its region -- two resources with
// the same signature differ only in `flex` attributes.
func consolidateSignature(r model.Resource, flex map[string]bool) string {
	fixed := make(map[string]any, len(r.Config))
	for k, v := range r.Config {
		if !flex[k] {
			fixed[k] = v
		}
	}
	b, _ := json.Marshal(fixed)
	return r.Region + "\x00" + string(b)
}

func buildGroup(items []placed, sub []int, catNamers map[string]*namer) *fgroup {
	rep := items[sub[0]].r

	diff := map[string]bool{}
	for k := range rep.Config {
		var first any
		for n, i := range sub {
			v := items[i].r.Config[k]
			if n == 0 {
				first = v
			} else if !reflect.DeepEqual(v, first) {
				diff[k] = true
			}
		}
	}
	if len(diff) == 0 {
		return nil // identical duplicates -- suspicious, leave them alone
	}
	diffKeys := make([]string, 0, len(diff))
	for k := range diff {
		diffKeys = append(diffKeys, k)
	}
	sort.Strings(diffKeys)

	keyAttr, keys := chooseForEachKeys(items, sub, diff)
	if keys == nil {
		return nil
	}

	cat := items[sub[0]].cat
	base := groupBaseName(rep, memberNames(items, sub))
	nm := catNamers[cat]
	if nm == nil {
		nm = newNamer()
		catNamers[cat] = nm
	}
	// the members already claimed their individual names in pass 1; release
	// them so the group can take the name they were derived from (e.g. the
	// three "virtualbeck*" MFA devices -> "virtualbeck", not "virtualbeck_2").
	for _, i := range sub {
		delete(nm.used, rep.TFType+"."+items[i].name)
	}
	return &fgroup{
		cat:      cat,
		tfType:   rep.TFType,
		name:     nm.claimBase(rep.TFType, base),
		diffKeys: diffKeys,
		keyAttr:  keyAttr,
		memIdx:   append([]int(nil), sub...),
		keys:     keys,
	}
}

// chooseForEachKeys returns the attribute used for the for_each map key and
// the per-member key values. It tries consolidateKeyAttrs in order, then the
// Name tag, then a stable hash of the resource id as a last resort.
func chooseForEachKeys(items []placed, sub []int, diff map[string]bool) (string, []string) {
	distinct := func(get func(int) string) []string {
		seen := map[string]bool{}
		ks := make([]string, 0, len(sub))
		for _, i := range sub {
			s := get(i)
			if s == "" || seen[s] {
				return nil
			}
			seen[s] = true
			ks = append(ks, s)
		}
		return ks
	}
	for _, c := range consolidateKeyAttrs {
		if !diff[c] {
			continue
		}
		if ks := distinct(func(i int) string {
			s, _ := items[i].r.Config[c].(string)
			return s
		}); ks != nil {
			return c, ks
		}
	}
	if ks := distinct(func(i int) string { return items[i].r.Tags["Name"] }); ks != nil {
		return "", ks
	}
	return "", distinct(func(i int) string { return shortHash(items[i].r.ID) })
}

func memberNames(items []placed, sub []int) []string {
	out := make([]string, 0, len(sub))
	for _, i := range sub {
		out = append(out, items[i].name)
	}
	return out
}

// groupBaseName picks the shared logical name for a for_each group: a
// purpose name for the types heuristicName knows, otherwise the common
// prefix of the members' individual names (private_1a / private_1b ->
// private), otherwise the type.
func groupBaseName(r model.Resource, names []string) string {
	switch r.TFType {
	case "aws_subnet":
		if b, _ := r.Config["map_public_ip_on_launch"].(bool); b {
			return "public"
		}
		return "private"
	case "aws_security_group":
		if h := heuristicName(r); h != "" {
			return h
		}
		return "sg"
	case "aws_iam_access_key":
		return "access_key"
	case "aws_iam_group_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_role_policy_attachment":
		return "policy"
	}
	if p := commonNamePrefix(names); p != "" {
		return p
	}
	if pre, ok := opaqueIDTypes[r.TFType]; ok {
		return pre
	}
	return strings.TrimPrefix(r.TFType, "aws_")
}

func commonNamePrefix(names []string) string {
	if len(names) == 0 {
		return ""
	}
	p := names[0]
	for _, n := range names[1:] {
		for !strings.HasPrefix(n, p) {
			p = p[:len(p)-1]
			if p == "" {
				return ""
			}
		}
	}
	p = strings.TrimRight(p, "_0123456789")
	p = strings.TrimRight(p, "_")
	if len(p) < 2 || !strings.ContainsFunc(p, func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		// no lowercase letter -> the "prefix" is a shared chunk of opaque ids
		// (AKIA..., i-0abc...), not a real name.
		return ""
	}
	return p
}

// claimBase registers a specific base name (already sanitized), resolving a
// collision with a numeric suffix -- the for_each-group counterpart to claim.
func (n *namer) claimBase(tfType, base string) string {
	base = sanitizeName(base)
	name := base
	for i := 2; n.used[tfType+"."+name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	n.used[tfType+"."+name] = true
	return name
}

// simpleVal reports whether a config value is a scalar, a flat list of
// scalars, or a flat map of scalars -- i.e. safe to lift verbatim into a
// for_each locals entry.
func simpleVal(v any) bool {
	switch x := v.(type) {
	case nil, string, float64, bool:
		return true
	case []any:
		for _, e := range x {
			if !simpleScalar(e) {
				return false
			}
		}
		return true
	case []string:
		return true
	case map[string]any:
		for _, e := range x {
			if !simpleScalar(e) {
				return false
			}
		}
		return true
	case map[string]string:
		return true
	}
	return false
}

func simpleScalar(v any) bool {
	switch v.(type) {
	case nil, string, float64, bool:
		return true
	}
	return false
}

// forEachConfig returns the representative member's config with every varying
// attribute replaced by an `each.key` / `each.value.<attr>` reference, plus
// the cty value for this group's `local` map. common tags are stripped from
// each member's tags before they land in the locals, matching what
// stripCommonTags does to an ordinary resource body.
func forEachConfig(g *fgroup, items []placed, common map[string]string) (map[string]any, cty.Value) {
	rep := items[g.memIdx[0]].r
	out := make(map[string]any, len(rep.Config))
	maps.Copy(out, rep.Config)
	diff := map[string]bool{}
	for _, k := range g.diffKeys {
		diff[k] = true
	}
	for _, k := range g.diffKeys {
		if k == g.keyAttr {
			out[k] = ref{trav: hcl.Traversal{
				hcl.TraverseRoot{Name: "each"}, hcl.TraverseAttr{Name: "key"},
			}}
			continue
		}
		out[k] = ref{trav: hcl.Traversal{
			hcl.TraverseRoot{Name: "each"},
			hcl.TraverseAttr{Name: "value"},
			hcl.TraverseAttr{Name: k},
		}}
	}

	entries := make(map[string]cty.Value, len(g.memIdx))
	for n, idx := range g.memIdx {
		obj := make(map[string]cty.Value, len(g.diffKeys))
		for _, k := range g.diffKeys {
			v := items[idx].r.Config[k]
			if k == "tags" {
				v = strippedTags(v, common)
			}
			obj[k] = anyToCty(v)
		}
		entries[g.keys[n]] = cty.ObjectVal(obj)
	}
	return out, cty.ObjectVal(entries)
}

func strippedTags(v any, common map[string]string) any {
	src := map[string]string{}
	switch t := v.(type) {
	case map[string]string:
		maps.Copy(src, t)
	case map[string]any:
		for k, e := range t {
			if s, ok := e.(string); ok {
				src[k] = s
			}
		}
	default:
		return v
	}
	for k, cv := range common {
		if src[k] == cv {
			delete(src, k)
		}
	}
	return src
}

// anyToCty converts a simpleVal into its cty form for a locals entry. A value
// that can't be represented becomes null (buildGroup only ever passes values
// simpleVal already accepted).
func anyToCty(v any) cty.Value {
	switch x := v.(type) {
	case nil:
		return cty.NullVal(cty.String)
	case string:
		return cty.StringVal(x)
	case float64:
		return cty.NumberFloatVal(x)
	case bool:
		return cty.BoolVal(x)
	case []any:
		if len(x) == 0 {
			return cty.ListValEmpty(cty.String)
		}
		vals := make([]cty.Value, 0, len(x))
		for _, e := range x {
			vals = append(vals, anyToCty(e))
		}
		return cty.TupleVal(vals)
	case []string:
		if len(x) == 0 {
			return cty.ListValEmpty(cty.String)
		}
		vals := make([]cty.Value, 0, len(x))
		for _, s := range x {
			vals = append(vals, cty.StringVal(s))
		}
		return cty.TupleVal(vals)
	case map[string]string:
		if len(x) == 0 {
			return cty.EmptyObjectVal
		}
		m := make(map[string]cty.Value, len(x))
		for k, s := range x {
			m[k] = cty.StringVal(s)
		}
		return cty.ObjectVal(m)
	case map[string]any:
		if len(x) == 0 {
			return cty.EmptyObjectVal
		}
		m := make(map[string]cty.Value, len(x))
		for k, e := range x {
			m[k] = anyToCty(e)
		}
		return cty.ObjectVal(m)
	default:
		return cty.NullVal(cty.String)
	}
}

// moduleLocalsFile renders the module's `locals` block: one entry per
// for_each group, an object keyed by instance key whose values carry that
// instance's varying attributes.
func moduleLocalsFile(m *modBuild) *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	lb := f.Body().AppendNewBlock("locals", nil).Body()
	names := make([]string, 0, len(m.locals))
	for n := range m.locals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lb.SetAttributeValue(n, m.locals[n])
	}
	return f
}

// keyedTraversal builds aws_x.name["key"].attr, or aws_x.name.attr when the
// target isn't a for_each member.
func keyedTraversal(t refTarget) hcl.Traversal {
	tr := hcl.Traversal{
		hcl.TraverseRoot{Name: t.tfType},
		hcl.TraverseAttr{Name: t.name},
	}
	if t.key != "" {
		tr = append(tr, hcl.TraverseIndex{Key: cty.StringVal(t.key)})
	}
	if t.attr != "" {
		tr = append(tr, hcl.TraverseAttr{Name: t.attr})
	}
	return tr
}
