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

// fgroup: near-identical resources emitted as one for_each.
type fgroup struct {
	cat    string
	tfType string
	name   string
	// Flat locals: same-named groups of different types collide.
	localName string
	diffKeys  []string
	keyAttr   string // "" means a synthetic key
	memIdx    []int
	keys      []string
}

// Preferred for_each key attributes, first distinct wins.
var consolidateKeyAttrs = []string{
	"availability_zone", "cidr_block", "cidr_ipv4", "cidr_ip",
	"name", "bucket", "domain_name", "identifier", "key", "path",
}

// consolidate groups runs of 3+ identical-shape resources.
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
			continue // on only some members: structural difference
		}
		allSimple, differ := true, false
		var first any
		for n, i := range idxs {
			v := items[i].r.Config[k]
			// Differing bools mean different configs; don't merge.
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
		return nil // identical duplicates are suspicious; leave them
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
	// free member names for the group base
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

// Key by attribute, Name tag, then ID hash.
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

// Group name: heuristic, shared prefix, then type.
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
		// no lowercase: shared opaque-ID chunk, not a name
		return ""
	}
	return p
}

func (n *namer) claimBase(tfType, base string) string {
	base = sanitizeName(base)
	name := base
	for i := 2; n.used[tfType+"."+name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	n.used[tfType+"."+name] = true
	return name
}

// simpleVal: scalar, or flat list/map of scalars.
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

// Varying attributes become each.key / each.value references.
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
