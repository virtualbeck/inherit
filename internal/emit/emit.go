// Package emit renders an inventory as schema-driven HCL.
package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/virtualbeck/inherit/model"
	"github.com/virtualbeck/inherit/tfschema"
	"github.com/zclconf/go-cty/cty"
)

type Options struct {
	// Environment only labels the example state key.
	Environment string

	// NoForEach disables for_each folding of identical resources.
	NoForEach bool
}

type Result struct {
	Dir     string
	Modules []string
	Blocks  int
	Imports []ImportSpec
	Skipped int // no schema for the type
	// Unmanaged counts attributes left to ignore_changes.
	Unmanaged int
}

// ImportSpec is one import: address plus ID.
type ImportSpec struct {
	Addr   string
	ID     string
	Cat    string
	TFType string
	Name   string
}

// ResourceAddr is the CLI address; keys are quoted.
func ResourceAddr(cat, tfType, name, key string) string {
	addr := "module." + cat + "." + tfType + "." + name
	if key != "" {
		addr += "[" + strconv.Quote(key) + "]"
	}
	return addr
}

type placed struct {
	r    model.Resource
	name string
	cat  string

	// for_each group membership:
	grp     *fgroup
	grpLead bool // renders the shared block
	grpKey  string
}

// refTarget is what a literal resolves to.
type refTarget struct{ cat, tfType, name, attr, key string }

// Domain-name IDs; matching them causes cycles.
var freeformIDTypes = map[string]bool{"aws_api_gateway_domain_name": true}

// Per-type fields that coincidentally match IDs (cycles seen).
var typeNoRefKeys = map[string]map[string]bool{
	"aws_service_discovery_http_namespace":        {"name": true},
	"aws_service_discovery_private_dns_namespace": {"name": true},
	"aws_service_discovery_public_dns_namespace":  {"name": true},
}

type outSpec struct {
	trav hcl.Traversal
	// a for expression over a whole group
	rawExpr string
	desc    string
}

// inputSpec is a variable the root must supply.
type inputSpec struct {
	desc string
	typ  string
}

type modBuild struct {
	body   *hclwrite.File
	outs   map[string]outSpec
	inputs map[string]inputSpec
	vars   []hoistedVar
	data   dataUse
	count  int
	// Foreign value per variable name, so resources share.
	externalRefValues map[string]any
	varTaken          map[string]bool
	needsLambdaZip    bool
	regionAliases     map[string]bool
	locals            map[string]cty.Value
}

// Write renders inv as root plus category modules.
func Write(inv model.Inventory, outDir string, opt Options) (Result, error) {
	sch, err := tfschema.Load()
	if err != nil {
		return Result{}, err
	}
	res := Result{Dir: outDir}
	defRegion := defaultRegion(inv)
	usedRegions := map[string]string{}

	// pass 1: items, categories, names
	catNamers := map[string]*namer{}
	var items []placed
	for _, r := range inv.Resources {
		if r.TFType == "" || r.Config == nil {
			continue
		}
		if _, ok := sch.Resource(r.TFType); !ok {
			res.Skipped++
			continue
		}
		items = append(items, placed{r: r, cat: categoryFor(r.TFType)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].cat != items[j].cat {
			return items[i].cat < items[j].cat
		}
		if items[i].r.TFType != items[j].r.TFType {
			return items[i].r.TFType < items[j].r.TFType
		}
		return items[i].r.ARN < items[j].r.ARN
	})
	// Sole resource of its type is named main.
	catTypeCount := map[string]map[string]int{}
	for _, it := range items {
		if catTypeCount[it.cat] == nil {
			catTypeCount[it.cat] = map[string]int{}
		}
		catTypeCount[it.cat][it.r.TFType]++
	}
	for i := range items {
		nm := catNamers[items[i].cat]
		if nm == nil {
			nm = newNamer()
			catNamers[items[i].cat] = nm
		}
		sole := catTypeCount[items[i].cat][items[i].r.TFType] == 1
		items[i].name = nm.claim(items[i].r, sole)
	}

	// Fold runs of 3+ identical resources into for_each.
	if !opt.NoForEach {
		// locals are flat per module, unlike resource addresses
		localNames := map[string]map[string]bool{}
		for _, g := range consolidate(items, catNamers) {
			used := localNames[g.cat]
			if used == nil {
				used = map[string]bool{}
				localNames[g.cat] = used
			}
			g.localName = g.name
			if used[g.localName] {
				g.localName = sanitizeName(g.name + "_" + strings.TrimPrefix(g.tfType, "aws_"))
				for i := 2; used[g.localName]; i++ {
					g.localName = fmt.Sprintf("%s_%s_%d", g.name, strings.TrimPrefix(g.tfType, "aws_"), i)
				}
			}
			used[g.localName] = true

			for n, mi := range g.memIdx {
				items[mi].grp = g
				items[mi].grpKey = g.keys[n]
				items[mi].grpLead = n == 0
				if n == 0 {
					items[mi].name = g.name
				}
			}
		}
	}

	common := commonTags(items, sch)

	// pass 2: index IDs; region-ambiguous IDs are skipped
	idx := map[string]refTarget{}
	idARN := map[string]string{}
	ambiguousID := map[string]bool{}
	for _, it := range items {
		name, key := it.name, ""
		if it.grp != nil {
			name, key = it.grp.name, it.grpKey
		}
		if it.r.ID != "" && !ambiguousID[it.r.ID] && !freeformIDTypes[it.r.TFType] {
			if prev, ok := idARN[it.r.ID]; ok && prev != it.r.ARN {
				ambiguousID[it.r.ID] = true
				delete(idx, it.r.ID)
			} else {
				idARN[it.r.ID] = it.r.ARN
				idx[it.r.ID] = refTarget{it.cat, it.r.TFType, name, idRefAttr(it.r.TFType), key}
			}
		}
		if it.r.ARN != "" {
			idx[it.r.ARN] = refTarget{it.cat, it.r.TFType, name, "arn", key}
		}
	}

	mods := map[string]*modBuild{}
	getmod := func(cat string) *modBuild {
		m := mods[cat]
		if m == nil {
			m = &modBuild{
				body: hclwrite.NewEmptyFile(), outs: map[string]outSpec{}, inputs: map[string]inputSpec{},
				externalRefValues: map[string]any{}, regionAliases: map[string]bool{},
				varTaken: map[string]bool{}, locals: map[string]cty.Value{},
			}
			mods[cat] = m
		}
		return m
	}
	wires := map[string]map[string]string{}
	rootArgs := map[string]map[string]cty.Value{}

	// pass 3: render resources into modules
	var unmanagedList []unmanaged
	for _, it := range items {
		// only the group lead renders
		if it.grp != nil && !it.grpLead {
			continue
		}
		m := getmod(it.cat)
		block, _ := sch.Resource(it.r.TFType)
		name := it.name
		if it.grp != nil {
			name = it.grp.name
		}
		selfAddr := it.r.TFType + "." + name

		srcCfg := it.r.Config
		var forEachLocal cty.Value
		ignore := unmanagedAttrs(it.r.Config)
		if it.grp != nil {
			srcCfg, forEachLocal = forEachConfig(it.grp, items, common)
			for _, mi := range it.grp.memIdx {
				ignore = unionAttrs(ignore, unmanagedAttrs(items[mi].r.Config))
			}
		}
		if len(ignore) > 0 {
			srcCfg = dropRedactedScalars(it.r.TFType, maps.Clone(srcCfg))
			unmanagedList = append(unmanagedList, unmanaged{addr: "module." + it.cat + "." + selfAddr, arn: it.r.ARN, attrs: ignore})
			res.Unmanaged += len(ignore)
		}

		cfg, _ := wireValue(srcCfg, it.cat, selfAddr, idx, getmod, wires).(map[string]any)
		cfg, _ = parameterize(cfg, it.r, defRegion, &m.data).(map[string]any)
		cfg, vars := hoist(cfg, name, it.r.TFType, m.varTaken)
		m.vars = append(m.vars, vars...)
		cfg = hoistExternalRefs(cfg, m, name, it.cat, it.r.TFType, rootArgs)
		cfg = scrubExternalIDs(cfg, m, name, it.cat, rootArgs)
		cfg = stripCommonTags(cfg, common)

		// Lambda code isn't recoverable; ship a placeholder zip.
		if (it.r.TFType == "aws_lambda_function" || it.r.TFType == "aws_lambda_layer_version") &&
			cfg != nil && !hasAny(cfg, "filename", "s3_bucket", "image_uri") {
			cfg["filename"] = tmpl{parts: []any{
				hcl.Traversal{hcl.TraverseRoot{Name: "path"}, hcl.TraverseAttr{Name: "module"}},
				"/" + lambdaPlaceholderZip,
			}}
			m.needsLambdaZip = true
		}

		b := m.body.Body().AppendNewBlock("resource", []string{it.r.TFType, name}).Body()
		if it.grp != nil {
			m.locals[it.grp.localName] = forEachLocal
			b.SetAttributeTraversal("for_each", hcl.Traversal{
				hcl.TraverseRoot{Name: "local"},
				hcl.TraverseAttr{Name: it.grp.localName},
			})
		}
		// Import ignores the per-resource region; alias the provider.
		if it.r.Region != "" && it.r.Region != defRegion {
			alias := sanitizeName(it.r.Region)
			m.regionAliases[alias] = true
			usedRegions[alias] = it.r.Region
			b.SetAttributeTraversal("provider", hcl.Traversal{
				hcl.TraverseRoot{Name: "aws"},
				hcl.TraverseAttr{Name: alias},
			})
		}
		writeBlock(b, cfg, block)
		if len(ignore) > 0 {
			writeIgnoreChanges(b, ignore)
		}
		m.body.Body().AppendNewline()
		m.count++
		res.Blocks++
	}

	cats := make([]string, 0, len(mods))
	for c := range mods {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	// A re-run must not inherit files it no longer writes.
	if err := removeStale(outDir); err != nil {
		return res, err
	}
	for _, c := range cats {
		m := mods[c]
		dir := filepath.Join(outDir, "modules", c)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return res, err
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), m.body.Bytes(), 0o644); err != nil {
			return res, err
		}
		if len(m.locals) > 0 {
			if err := os.WriteFile(filepath.Join(dir, "locals.tf"), moduleLocalsFile(m).Bytes(), 0o644); err != nil {
				return res, err
			}
		}
		if f := moduleVariablesFile(m); f != nil {
			if err := os.WriteFile(filepath.Join(dir, "variables.tf"), f.Bytes(), 0o644); err != nil {
				return res, err
			}
		}
		if len(m.outs) > 0 {
			if err := os.WriteFile(filepath.Join(dir, "outputs.tf"), moduleOutputsFile(m).Bytes(), 0o644); err != nil {
				return res, err
			}
		}
		if m.data.any() {
			if err := os.WriteFile(filepath.Join(dir, "data.tf"), dataFile(m.data).Bytes(), 0o644); err != nil {
				return res, err
			}
		}
		if len(m.regionAliases) > 0 {
			if err := os.WriteFile(filepath.Join(dir, "versions.tf"), moduleVersionsFile(m).Bytes(), 0o644); err != nil {
				return res, err
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(moduleReadme(c, m)), 0o644); err != nil {
			return res, err
		}
		if m.needsLambdaZip {
			if err := os.WriteFile(filepath.Join(dir, lambdaPlaceholderZip), emptyZip, 0o644); err != nil {
				return res, err
			}
		}
		res.Modules = append(res.Modules, c)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "backend.tf"), []byte(backendTF(inv.Account, opt.Environment)), 0o644); err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "README.md"), []byte(rootReadme(inv, mods, res.Blocks, common)), 0o644); err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "versions.tf"), versionsFile().Bytes(), 0o644); err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "providers.tf"), providersFile(defRegion, usedRegions, common).Bytes(), 0o644); err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "main.tf"), rootMainFile(cats, wires, rootArgs, mods).Bytes(), 0o644); err != nil {
		return res, err
	}
	if len(unmanagedList) > 0 {
		if err := os.WriteFile(filepath.Join(outDir, "UNMANAGED_FIELDS.md"), []byte(unmanagedDoc(unmanagedList)), 0o644); err != nil {
			return res, err
		}
	}

	imp := hclwrite.NewEmptyFile()
	for _, it := range items {
		id := importID(it.r, inv.Partition, inv.Account)
		if id == "" {
			continue
		}
		name, addr := it.name, ""
		to := hcl.Traversal{
			hcl.TraverseRoot{Name: "module"},
			hcl.TraverseAttr{Name: it.cat},
			hcl.TraverseAttr{Name: it.r.TFType},
		}
		if it.grp != nil {
			name = it.grp.name
			to = append(to, hcl.TraverseAttr{Name: name},
				hcl.TraverseIndex{Key: cty.StringVal(it.grpKey)})
			addr = ResourceAddr(it.cat, it.r.TFType, name, it.grpKey)
		} else {
			to = append(to, hcl.TraverseAttr{Name: name})
			addr = ResourceAddr(it.cat, it.r.TFType, name, "")
		}
		ib := imp.Body().AppendNewBlock("import", nil).Body()
		ib.SetAttributeTraversal("to", to)
		ib.SetAttributeValue("id", cty.StringVal(id))
		imp.Body().AppendNewline()
		res.Imports = append(res.Imports, ImportSpec{
			Addr:   addr,
			ID:     id,
			Cat:    it.cat,
			TFType: it.r.TFType,
			Name:   name,
		})
	}
	header := "# Generated by inherit. `tofu plan` shows what these would import.\n" +
		"# `inherit import` brings them into local state. This file carries raw AWS\n" +
		"# identifiers (an aws_iam_access_key's import ID is the access key ID itself);\n" +
		"# once everything is imported it has done its job and can be deleted.\n\n"
	if err := os.WriteFile(filepath.Join(outDir, "imports.tf"), append([]byte(header), imp.Bytes()...), 0o644); err != nil {
		return res, err
	}

	return res, nil
}

// Never wired as references; each caused collisions.
var noRefKeys = map[string]bool{"dimensions": true, "task_definition": true, "name": true, "tags": true}

// wireValue turns literals that match resources into references.
func wireValue(v any, selfCat, selfAddr string, idx map[string]refTarget, getmod func(string) *modBuild, wires map[string]map[string]string) any {
	switch t := v.(type) {
	case string:
		tgt, ok := idx[t]
		if !ok || tgt.tfType+"."+tgt.name == selfAddr {
			return t
		}
		if tgt.cat == selfCat {
			return ref{keyedTraversal(tgt)}
		}
		if tgt.key != "" {
			// One output per group, not per member.
			out := sanitizeName(tgt.name + "_" + tgt.attr + "s")
			getmod(tgt.cat).outs[out] = outSpec{
				rawExpr: fmt.Sprintf("{ for k, v in %s.%s : k => v.%s }", tgt.tfType, tgt.name, tgt.attr),
				desc:    tgt.attr + " of each " + tgt.tfType + "." + tgt.name + ", keyed the same as local." + tgt.name,
			}
			varName := sanitizeName(tgt.cat + "_" + tgt.name + "_" + tgt.attr + "s")
			getmod(selfCat).inputs[varName] = inputSpec{
				desc: tgt.attr + " of each " + tgt.tfType + "." + tgt.name + " (module " + tgt.cat + "), wired in the root",
				typ:  "map(string)",
			}
			if wires[selfCat] == nil {
				wires[selfCat] = map[string]string{}
			}
			wires[selfCat][varName] = "module." + tgt.cat + "." + out
			return ref{hcl.Traversal{
				hcl.TraverseRoot{Name: "var"},
				hcl.TraverseAttr{Name: varName},
				hcl.TraverseIndex{Key: cty.StringVal(tgt.key)},
			}}
		}
		out := sanitizeName(tgt.name + "_" + tgt.attr)
		getmod(tgt.cat).outs[out] = outSpec{
			trav: keyedTraversal(tgt),
			desc: tgt.attr + " of " + tgt.tfType + "." + tgt.name,
		}
		varName := sanitizeName(tgt.cat + "_" + tgt.name + "_" + tgt.attr)
		getmod(selfCat).inputs[varName] = inputSpec{
			desc: tgt.attr + " of " + tgt.tfType + "." + tgt.name + " (module " + tgt.cat + "), wired in the root",
			typ:  "string",
		}
		if wires[selfCat] == nil {
			wires[selfCat] = map[string]string{}
		}
		wires[selfCat][varName] = "module." + tgt.cat + "." + out
		return ref{hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: varName}}}
	case map[string]any:
		selfType, _, _ := strings.Cut(selfAddr, ".")
		m := make(map[string]any, len(t))
		for k, e := range t {
			if noRefKeys[k] || typeNoRefKeys[selfType][k] {
				m[k] = e
				continue
			}
			m[k] = wireValue(e, selfCat, selfAddr, idx, getmod, wires)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, e := range t {
			s[i] = wireValue(e, selfCat, selfAddr, idx, getmod, wires)
		}
		return s
	default:
		return v
	}
}

func moduleVariablesFile(m *modBuild) *hclwrite.File {
	if len(m.vars) == 0 && len(m.inputs) == 0 {
		return nil
	}
	f := hclwrite.NewEmptyFile()
	inputs := make([]string, 0, len(m.inputs))
	for v := range m.inputs {
		inputs = append(inputs, v)
	}
	sort.Strings(inputs)
	for _, v := range inputs {
		spec := m.inputs[v]
		typ := spec.typ
		if typ == "" {
			typ = "string"
		}
		b := f.Body().AppendNewBlock("variable", []string{v}).Body()
		b.SetAttributeRaw("type", rawExprTokens(typ))
		if spec.desc != "" {
			b.SetAttributeValue("description", cty.StringVal(spec.desc))
		}
		f.Body().AppendNewline()
	}
	sort.Slice(m.vars, func(i, j int) bool { return m.vars[i].name < m.vars[j].name })
	seen := map[string]bool{}
	for _, v := range m.vars {
		if seen[v.name] {
			continue
		}
		seen[v.name] = true
		b := f.Body().AppendNewBlock("variable", []string{v.name}).Body()
		if v.desc != "" {
			b.SetAttributeValue("description", cty.StringVal(v.desc))
		}
		b.SetAttributeValue("default", v.value)
		f.Body().AppendNewline()
	}
	return f
}

func moduleOutputsFile(m *modBuild) *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	names := make([]string, 0, len(m.outs))
	for n := range m.outs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := f.Body().AppendNewBlock("output", []string{n}).Body()
		if d := m.outs[n].desc; d != "" {
			b.SetAttributeValue("description", cty.StringVal(d))
		}
		if raw := m.outs[n].rawExpr; raw != "" {
			b.SetAttributeRaw("value", rawExprTokens(raw))
		} else {
			b.SetAttributeTraversal("value", m.outs[n].trav)
		}
		f.Body().AppendNewline()
	}
	return f
}

func rootMainFile(cats []string, wires map[string]map[string]string, rootArgs map[string]map[string]cty.Value, mods map[string]*modBuild) *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	for _, c := range cats {
		b := f.Body().AppendNewBlock("module", []string{c}).Body()
		b.SetAttributeValue("source", cty.StringVal("./modules/"+c))
		if aliases := mods[c].regionAliases; len(aliases) > 0 {
			names := make([]string, 0, len(aliases))
			for a := range aliases {
				names = append(names, a)
			}
			sort.Strings(names)
			var src strings.Builder
			src.WriteString("{\n  aws = aws\n")
			for _, a := range names {
				fmt.Fprintf(&src, "  aws.%s = aws.%s\n", a, a)
			}
			src.WriteString("}")
			b.SetAttributeRaw("providers", rawExprTokens(src.String()))
		}
		w := wires[c]
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.Split(w[k], ".")
			b.SetAttributeTraversal(k, hcl.Traversal{
				hcl.TraverseRoot{Name: parts[0]},
				hcl.TraverseAttr{Name: parts[1]},
				hcl.TraverseAttr{Name: parts[2]},
			})
		}
		ra := rootArgs[c]
		raNames := make([]string, 0, len(ra))
		for k := range ra {
			raNames = append(raNames, k)
		}
		sort.Strings(raNames)
		for _, k := range raNames {
			b.SetAttributeValue(k, ra[k])
		}
		f.Body().AppendNewline()
	}
	return f
}

func dataFile(u dataUse) *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	add := func(t, instance string, alias string) {
		b := f.Body().AppendNewBlock("data", []string{t, instance}).Body()
		if alias != "" {
			b.SetAttributeTraversal("provider", hcl.Traversal{
				hcl.TraverseRoot{Name: "aws"},
				hcl.TraverseAttr{Name: alias},
			})
		}
		f.Body().AppendNewline()
	}
	if u.region {
		add("aws_region", "current", "")
	}
	aliases := make([]string, 0, len(u.regionAliases))
	for a := range u.regionAliases {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, a := range aliases {
		// same alias as the resources it serves
		add("aws_region", a, a)
	}
	if u.account {
		add("aws_caller_identity", "current", "")
	}
	if u.part {
		add("aws_partition", "current", "")
	}
	return f
}

func versionsFile() *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	tfBlock := f.Body().AppendNewBlock("terraform", nil).Body()
	tfBlock.SetAttributeValue("required_version", cty.StringVal(">= 1.6"))
	rp := tfBlock.AppendNewBlock("required_providers", nil).Body()
	rp.SetAttributeValue("aws", cty.ObjectVal(map[string]cty.Value{
		"source":  cty.StringVal("hashicorp/aws"),
		"version": cty.StringVal("~> 6.0"),
	}))
	return f
}

// default_tags is per provider; aliases repeat it.
func providersFile(defRegion string, usedRegions map[string]string, defaultTags map[string]string) *hclwrite.File {
	f := hclwrite.NewEmptyFile()
	addDefaultTags := func(body *hclwrite.Body) {
		if len(defaultTags) == 0 {
			return
		}
		tags := make(map[string]cty.Value, len(defaultTags))
		for k, v := range defaultTags {
			tags[k] = cty.StringVal(v)
		}
		body.AppendNewBlock("default_tags", nil).Body().SetAttributeValue("tags", cty.MapVal(tags))
	}

	pb := f.Body().AppendNewBlock("provider", []string{"aws"}).Body()
	if defRegion != "" {
		pb.SetAttributeValue("region", cty.StringVal(defRegion))
	}
	addDefaultTags(pb)

	aliases := make([]string, 0, len(usedRegions))
	for a := range usedRegions {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		f.Body().AppendNewline()
		apb := f.Body().AppendNewBlock("provider", []string{"aws"}).Body()
		apb.SetAttributeValue("alias", cty.StringVal(alias))
		apb.SetAttributeValue("region", cty.StringVal(usedRegions[alias]))
		addDefaultTags(apb)
	}
	return f
}

// Only tags on every taggable resource qualify.
func commonTags(items []placed, sch *tfschema.Schema) map[string]string {
	var common map[string]string
	first := true
	for _, it := range items {
		block, _ := sch.Resource(it.r.TFType)
		if block == nil || !block.Has("tags") {
			continue
		}
		if first {
			common = make(map[string]string, len(it.r.Tags))
			maps.Copy(common, it.r.Tags)
			first = false
			continue
		}
		for k, v := range common {
			if it.r.Tags[k] != v {
				delete(common, k)
			}
		}
	}
	return common
}

func stripCommonTags(cfg map[string]any, common map[string]string) map[string]any {
	if cfg == nil || len(common) == 0 {
		return cfg
	}
	tm, ok := cfg["tags"].(map[string]string)
	if !ok {
		return cfg
	}
	trimmed := make(map[string]string, len(tm))
	for k, v := range tm {
		if cv, isCommon := common[k]; isCommon && cv == v {
			continue
		}
		trimmed[k] = v
	}
	if len(trimmed) == 0 {
		delete(cfg, "tags")
	} else {
		cfg["tags"] = trimmed
	}
	return cfg
}

// Modules declare aliased providers; the root passes them.
func moduleVersionsFile(m *modBuild) *hclwrite.File {
	names := make([]string, 0, len(m.regionAliases))
	for a := range m.regionAliases {
		names = append(names, a)
	}
	sort.Strings(names)
	aliasRefs := make([]string, len(names))
	for i, a := range names {
		aliasRefs[i] = "aws." + a
	}

	f := hclwrite.NewEmptyFile()
	tfBlock := f.Body().AppendNewBlock("terraform", nil).Body()
	rp := tfBlock.AppendNewBlock("required_providers", nil).Body()
	src := fmt.Sprintf("{\n  source                 = \"hashicorp/aws\"\n  configuration_aliases  = [%s]\n}", strings.Join(aliasRefs, ", "))
	rp.SetAttributeRaw("aws", rawExprTokens(src))
	return f
}

// rawExprTokens parses HCL that cty.Value can't express.
func rawExprTokens(src string) hclwrite.Tokens {
	f, diags := hclwrite.ParseConfig([]byte("x = "+src), "generated.tf", hcl.InitialPos)
	if diags.HasErrors() {
		// our own input; failure is a bug
		panic("rawExprTokens: " + diags.Error())
	}
	return f.Body().GetAttribute("x").Expr().BuildTokens(nil)
}

func writeBlock(body *hclwrite.Body, cfg map[string]any, block *tfschema.Block) {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := cfg[k]

		if _, isRef := v.(ref); !isRef {
			if bt, ok := block.NestedBlock(k); ok {
				switch elems := v.(type) {
				case map[string]any:
					writeBlock(body.AppendNewBlock(k, nil).Body(), elems, bt.Block)
				case []any:
					for _, e := range elems {
						if m, ok := e.(map[string]any); ok {
							writeBlock(body.AppendNewBlock(k, nil).Body(), m, bt.Block)
						}
					}
				}
				continue
			}
		}

		attr, ok := block.Attr(k)
		if !ok {
			continue
		}
		var typ *tfschema.Type
		if attr != nil {
			typ = attr.Type
		}
		// Object attributes reject partial literals; pad with null.
		if names := objectAttrNames(attr); names != nil {
			v = padObjects(v, names)
		}
		if tk := valueTokens(v, typ); tk != nil {
			body.SetAttributeRaw(k, tk)
		}
	}
}

type nullTok struct{}

const lambdaPlaceholderZip = "lambda_placeholder.zip"

// end-of-central-directory record only
var emptyZip = []byte{
	0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

func hasAny(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func objectAttrNames(a *tfschema.Attribute) []string {
	if a == nil {
		return nil
	}
	if t := a.Type; t != nil {
		switch {
		case t.IsCollectionOfObject():
			return keysOf(t.Elem.Attrs)
		case t.Kind == tfschema.KindObject:
			return keysOf(t.Attrs)
		}
	}
	if a.Nested != nil && (a.NestedMode == "list" || a.NestedMode == "set" || a.NestedMode == "single") {
		return keysOf(a.Nested.Attributes)
	}
	return nil
}

func keysOf[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func padObjects(v any, names []string) any {
	pad := func(m map[string]any) map[string]any {
		for _, n := range names {
			if _, ok := m[n]; !ok {
				m[n] = nullTok{}
			}
		}
		return m
	}
	switch x := v.(type) {
	case map[string]any:
		return pad(x)
	case []any:
		for i, e := range x {
			if m, ok := e.(map[string]any); ok {
				x[i] = pad(m)
			}
		}
		return x
	}
	return v
}

func valueTokens(v any, t *tfschema.Type) hclwrite.Tokens {
	switch x := v.(type) {
	case ref:
		return hclwrite.TokensForTraversal(x.trav)
	case tmpl:
		return templateTokens(x)
	case nullTok:
		return hclwrite.TokensForValue(cty.NullVal(cty.DynamicPseudoType))
	case nil:
		return nil
	case string:
		// set deliberately by a hydrator
		return hclwrite.TokensForValue(cty.StringVal(x))
	case bool:
		return hclwrite.TokensForValue(cty.BoolVal(x))
	case float64:
		return hclwrite.TokensForValue(cty.NumberFloatVal(x))
	case int64:
		return hclwrite.TokensForValue(cty.NumberIntVal(x))
	case int32:
		return hclwrite.TokensForValue(cty.NumberIntVal(int64(x)))
	case int:
		return hclwrite.TokensForValue(cty.NumberIntVal(int64(x)))
	case []string:
		el := make([]hclwrite.Tokens, 0, len(x))
		for _, s := range x {
			el = append(el, hclwrite.TokensForValue(cty.StringVal(s)))
		}
		if len(el) == 0 {
			return nil
		}
		return hclwrite.TokensForTuple(el)
	case []any:
		var elemT *tfschema.Type
		if t != nil {
			elemT = t.Elem
		}
		el := make([]hclwrite.Tokens, 0, len(x))
		for _, e := range x {
			if tk := valueTokens(e, elemT); tk != nil {
				el = append(el, tk)
			}
		}
		if len(el) == 0 {
			return nil
		}
		return hclwrite.TokensForTuple(el)
	case map[string]string:
		attrs := make([]hclwrite.ObjectAttrTokens, 0, len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			attrs = append(attrs, hclwrite.ObjectAttrTokens{
				Name:  objKey(k),
				Value: hclwrite.TokensForValue(cty.StringVal(x[k])),
			})
		}
		if len(attrs) == 0 {
			return nil
		}
		return hclwrite.TokensForObject(attrs)
	case map[string]any:
		var subT *tfschema.Type
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrs := make([]hclwrite.ObjectAttrTokens, 0, len(x))
		for _, k := range keys {
			if t != nil {
				if t.Kind == tfschema.KindMap {
					subT = t.Elem
				} else if t.Attrs != nil {
					subT = t.Attrs[k]
				}
			}
			if tk := valueTokens(x[k], subT); tk != nil {
				attrs = append(attrs, hclwrite.ObjectAttrTokens{Name: objKey(k), Value: tk})
			}
		}
		if len(attrs) == 0 {
			return nil
		}
		return hclwrite.TokensForObject(attrs)
	default:
		return nil
	}
}

// Hand-built: TokensForValue would escape the ${.
func templateTokens(x tmpl) hclwrite.Tokens {
	quotedLit := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "${", "$${", "%{", "%%{")
	toks := hclwrite.Tokens{{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)}}
	for _, p := range x.parts {
		switch pp := p.(type) {
		case string:
			toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(quotedLit.Replace(pp))})
		case hcl.Traversal:
			toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenTemplateInterp, Bytes: []byte("${")})
			toks = append(toks, hclwrite.TokensForTraversal(pp)...)
			toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenTemplateSeqEnd, Bytes: []byte("}")})
		}
	}
	toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)})
	return toks
}

var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func objKey(k string) hclwrite.Tokens {
	if identRE.MatchString(k) {
		return hclwrite.TokensForIdentifier(k)
	}
	return hclwrite.TokensForValue(cty.StringVal(k))
}

func defaultRegion(inv model.Inventory) string {
	for _, r := range inv.Resources {
		if r.Region == "us-east-1" {
			return "us-east-1"
		}
	}
	counts := map[string]int{}
	for _, r := range inv.Resources {
		if r.Region != "" {
			counts[r.Region]++
		}
	}
	best, n := "", 0
	for k, v := range counts {
		if v > n {
			best, n = k, v
		}
	}
	return best
}

// ref renders as a bare traversal.
type ref struct{ trav hcl.Traversal }

func rootName(t hcl.Traversal) string {
	if len(t) < 2 {
		return ""
	}
	root, _ := t[0].(hcl.TraverseRoot)
	attr, _ := t[1].(hcl.TraverseAttr)
	return root.Name + "." + attr.Name
}

// idRefAttr is the attribute exposing this ID.
func idRefAttr(tfType string) string {
	switch tfType {
	case "aws_db_instance":
		return "identifier"
	default:
		return "id"
	}
}

// Types the provider can't import.
var noImportTypes = map[string]bool{
	"aws_guardduty_detector_feature":                   true,
	"aws_guardduty_organization_configuration_feature": true,
}

func importID(r model.Resource, partition, account string) string {
	id := rawImportID(r)
	// Older inventories hold the bare setting ID.
	if r.TFType == "aws_ssm_service_setting" && strings.HasPrefix(id, "/") && r.Region != "" && account != "" {
		if partition == "" {
			partition = "aws"
		}
		return fmt.Sprintf("arn:%s:ssm:%s:%s:servicesetting%s", partition, r.Region, account, id)
	}
	return id
}

func rawImportID(r model.Resource) string {
	if noImportTypes[r.TFType] {
		return ""
	}
	if r.ImportID != "" {
		return r.ImportID
	}
	switch r.TFType {
	case "aws_iam_role", "aws_iam_user", "aws_iam_group", "aws_iam_instance_profile":
		// imported by name; the ARN id carries the path
		return r.ID[strings.LastIndexByte(r.ID, '/')+1:]
	case "aws_iam_policy", "aws_sns_topic",
		"aws_resourceexplorer2_index", "aws_resourceexplorer2_view",
		"aws_iam_openid_connect_provider", "aws_iam_saml_provider",
		"aws_secretsmanager_secret", "aws_lb", "aws_lb_target_group",
		"aws_lb_listener", "aws_acm_certificate", "aws_ecs_task_definition",
		"aws_sfn_activity", "aws_sfn_state_machine", "aws_lambda_code_signing_config":
		// these import by full ARN
		return r.ARN
	case "aws_sqs_queue":
		if r.Region != "" && r.Account != "" {
			return fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", r.Region, r.Account, r.ID)
		}
		return ""
	case "aws_cloudformation_stack":
		// id is <name>/<uuid>; imported by name
		if n, _, ok := strings.Cut(r.ID, "/"); ok {
			return n
		}
		return r.ID
	case "aws_cloudformation_stack_set":
		// id is <name>:<uuid>; imported by name
		if n, _, ok := strings.Cut(r.ID, ":"); ok {
			return n
		}
		return r.ID
	case "aws_ssm_parameter":
		// the hydrator resolved the real leading-slash name
		if name, ok := r.Config["name"].(string); ok && name != "" {
			return name
		}
		return r.ID
	case "aws_key_pair":
		// imported by key_name, not key-id
		if name, ok := r.Config["key_name"].(string); ok && name != "" {
			return name
		}
		return r.ID
	case "aws_service_discovery_private_dns_namespace":
		// import ID is NAMESPACE_ID:VPC_ID
		if vpc, ok := r.Config["vpc"].(string); ok && vpc != "" {
			return r.ID + ":" + vpc
		}
		return r.ID
	default:
		return r.ID
	}
}

var nameSanitize = regexp.MustCompile(`[^A-Za-z0-9_]+`)

const maxLogicalName = 48

// IDs without a human name; hash fallback.
var opaqueIDTypes = map[string]string{
	"aws_vpc":                    "vpc",
	"aws_subnet":                 "subnet",
	"aws_security_group":         "sg",
	"aws_route_table":            "rt",
	"aws_internet_gateway":       "igw",
	"aws_nat_gateway":            "nat",
	"aws_eip":                    "eip",
	"aws_network_acl":            "nacl",
	"aws_vpc_endpoint":           "vpce",
	"aws_vpc_peering_connection": "pcx",
	"aws_vpc_dhcp_options":       "dhcp",
	"aws_customer_gateway":       "cgw",
	"aws_vpn_gateway":            "vgw",
	"aws_vpn_connection":         "vpn",
	"aws_ec2_transit_gateway":    "tgw",
	"aws_ebs_volume":             "vol",
	"aws_network_interface":      "eni",
}

type namer struct {
	used map[string]bool
}

func newNamer() *namer { return &namer{used: map[string]bool{}} }

// claim names a resource, deduplicated per type.
func (n *namer) claim(r model.Resource, sole bool) string {
	base := sanitizeName(rawName(r, sole))
	name := base
	for i := 2; n.used[r.TFType+"."+name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	n.used[r.TFType+"."+name] = true
	return name
}

// rawName: sole, Name tag, heuristic, ID, name, hash.
func rawName(r model.Resource, sole bool) string {
	if sole {
		return "main"
	}
	// A lazily enumerated Name tag loses to heuristics.
	if v := r.Tags["Name"]; v != "" && !lazyEnumeration(v) {
		return v
	}
	if h := heuristicName(r); h != "" {
		return h
	}
	if v := r.Tags["Name"]; v != "" {
		return v
	}
	switch r.TFType {
	case "aws_cloudformation_stack", "aws_resourceexplorer2_view": // id "<name>/<uuid>"
		if s, _, ok := strings.Cut(r.ID, "/"); ok {
			return s
		}
	case "aws_cloudformation_stack_set": // id "<name>:<uuid>"
		if s, _, ok := strings.Cut(r.ID, ":"); ok {
			return s
		}
	case "aws_resourceexplorer2_index": // bare uuid; one per region
		return "current"
	}
	if prefix, ok := opaqueIDTypes[r.TFType]; ok {
		if nm := cfgString(r.Config, "name"); nm != "" && !looksLikeAWSID(nm) {
			return nm
		}
		return prefix + "_" + shortHash(r.ID)
	}
	return lastNameSegment(r.ID)
}

// heuristicName guesses a purpose name; "" if none.
func heuristicName(r model.Resource) string {
	switch r.TFType {
	case "aws_security_group":
		// rules are separate resources; use the group's text
		txt := strings.ToLower(cfgString(r.Config, "name") + " " + cfgString(r.Config, "description"))
		switch {
		case strings.Contains(txt, "https") || strings.Contains(txt, "443"):
			return "sg_https"
		case strings.Contains(txt, "http") || strings.Contains(txt, " web"):
			return "sg_http"
		case strings.Contains(txt, "ssh") || strings.Contains(txt, "bastion"):
			return "sg_ssh"
		case strings.Contains(txt, "rdp"):
			return "sg_rdp"
		case strings.Contains(txt, "postgres") || strings.Contains(txt, "5432"):
			return "sg_postgres"
		case strings.Contains(txt, "mysql") || strings.Contains(txt, "3306") || strings.Contains(txt, "aurora"):
			return "sg_mysql"
		case strings.Contains(txt, "database") || strings.Contains(txt, " rds") || strings.Contains(txt, " db"):
			return "sg_db"
		case strings.Contains(txt, "lambda"):
			return "sg_lambda"
		case strings.Contains(txt, "load balancer") || strings.Contains(txt, " alb") || strings.Contains(txt, " nlb") || strings.Contains(txt, " elb"):
			return "sg_lb"
		}
	case "aws_subnet":
		tier := "private"
		if b, _ := r.Config["map_public_ip_on_launch"].(bool); b {
			tier = "public"
		}
		if az := cfgString(r.Config, "availability_zone"); az != "" {
			if i := strings.LastIndex(az, "-"); i >= 0 && i < len(az)-1 {
				return tier + "_" + az[i+1:] // us-east-1a -> private_1a
			}
		}
		return tier
	case "aws_route_table":
		if routeTableHasIGW(r.Config) {
			return "public"
		}
		return "private"
	case "aws_iam_role":
		if p := iamTrustService(r.Config); p != "" {
			return sanitizeName(strings.TrimSuffix(p, ".amazonaws.com"))
		}
	case "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule":
		return sgRuleName(r)
	}
	return ""
}

var wellKnownPorts = map[int]string{
	20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 111: "rpcbind", 123: "ntp", 161: "snmp",
	179: "bgp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	500: "ike", 587: "submission", 636: "ldaps", 989: "ftps_data", 990: "ftps",
	1194: "openvpn", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2181: "zookeeper",
	3000: "grafana", 3306: "mysql", 3389: "rdp", 4500: "ipsec_nat",
	5432: "postgres", 5439: "redshift", 5601: "kibana", 5672: "amqp", 6379: "redis",
	6443: "k8s_api", 8080: "http_alt", 8443: "https_alt", 9042: "cassandra",
	9090: "prometheus", 9092: "kafka", 9200: "opensearch", 9300: "opensearch_transport",
	10250: "kubelet", 11211: "memcached", 15672: "rabbitmq_mgmt", 27017: "mongodb",
	51820: "wireguard",
}

// sgRuleName: e.g. ingress_https, egress_all, ingress_5000.
func sgRuleName(r model.Resource) string {
	dir := "ingress"
	if r.TFType == "aws_vpc_security_group_egress_rule" {
		dir = "egress"
	}
	proto := strings.ToLower(cfgString(r.Config, "ip_protocol"))
	if proto == "" || proto == "-1" {
		return dir + "_all"
	}
	from, okF := cfgInt(r.Config, "from_port")
	to, okT := cfgInt(r.Config, "to_port")
	if !okF && !okT {
		return dir + "_" + sanitizeName(proto) // e.g. icmp, with no ports
	}
	if from == to {
		if n := wellKnownPorts[from]; n != "" {
			return dir + "_" + n
		}
		if proto == "tcp" {
			return fmt.Sprintf("%s_%d", dir, from)
		}
		return fmt.Sprintf("%s_%s_%d", dir, sanitizeName(proto), from)
	}
	return fmt.Sprintf("%s_%d_%d", dir, from, to)
}

// JSON numbers arrive as float64.
func cfgInt(cfg map[string]any, key string) (int, bool) {
	switch n := cfg[key].(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func cfgString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return s
}

// Names like sg1, subnet_02: counted, not named.
var lazyEnumerationRe = regexp.MustCompile(`(?i)^[a-z]{1,8}[-_ ]?\d{1,3}$`)

func lazyEnumeration(s string) bool { return lazyEnumerationRe.MatchString(s) }

func looksLikeAWSID(s string) bool {
	i := strings.IndexByte(s, '-')
	if i <= 0 || i > 8 {
		return false
	}
	for _, c := range s[i+1:] {
		hex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !hex {
			return false
		}
	}
	return len(s) > i+1
}

func routeTableHasIGW(cfg map[string]any) bool {
	routes, _ := cfg["route"].([]any)
	for _, rt := range routes {
		m, _ := rt.(map[string]any)
		if gw := cfgString(m, "gateway_id"); strings.HasPrefix(gw, "igw-") {
			return true
		}
	}
	return false
}

func iamTrustService(cfg map[string]any) string {
	doc := cfgString(cfg, "assume_role_policy")
	for _, svc := range []string{
		"lambda", "ec2", "ecs-tasks", "eks", "rds", "glue", "states",
		"apigateway", "events", "scheduler", "firehose", "codebuild", "codepipeline",
	} {
		if strings.Contains(doc, `"`+svc+`.amazonaws.com"`) {
			return svc
		}
	}
	return ""
}

// lastNameSegment returns an ID's last part.
func lastNameSegment(id string) string {
	s := id
	if i := strings.LastIndexAny(s, "/"); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	} else if strings.HasPrefix(id, "arn:") {
		if i := strings.LastIndex(s, ":"); i >= 0 && i < len(s)-1 {
			s = s[i+1:]
		}
	}
	return s
}

func sanitizeName(raw string) string {
	full := strings.Trim(nameSanitize.ReplaceAllString(raw, "_"), "_")
	base := full
	if len(base) > maxLogicalName {
		base = strings.Trim(base[:maxLogicalName-9], "_") + "_" + shortHash(full)
	}
	if base == "" || (!isAlpha(base[0]) && base[0] != '_') {
		base = "r_" + base
	}
	return base
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

func isAlpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
