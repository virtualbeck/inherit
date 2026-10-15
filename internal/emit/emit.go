// Package emit renders a hydrated inventory as OpenTofu/Terraform HCL. It is
// driven by the provider schema (tfschema), so every value lands as an
// argument, a map, or a nested block exactly as the provider expects. The
// output is valid by construction and needs no `tofu fmt` afterwards.
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

// Options controls how Write lays out the generated project.
type Options struct {
	// Environment labels which environment this account represents (e.g.
	// "dev"). internal/cli requires it on every real run (one account, one
	// environment, 1:1) and lowercases it before it gets here; empty is
	// only reachable through this package's own tests/direct API use, and
	// falls back to a flat example state key. Doesn't affect the module
	// tree or output directory at all -- only the example state key in the
	// generated backend.tf.
	Environment string

	// NoForEach disables §5.3 consolidation -- an escape hatch. By default
	// runs of >= 3 structurally-identical resources of the same type are
	// folded into a single `for_each` block over a `local` map rather than
	// emitted as subnet_1 / subnet_2 / subnet_3.
	NoForEach bool
}

// Result reports what was written.
type Result struct {
	Dir     string
	Modules []string
	Blocks  int
	Imports []ImportSpec
	Skipped int // hydrated resources with no schema
	// Unmanaged counts resource attributes left under ignore_changes
	// because they carried redacted secrets (see UNMANAGED_FIELDS.md).
	Unmanaged int
}

// ImportSpec is one `terraform import <addr> <id>` pair. Addr is
// module-qualified (module.<category>.<type>.<name>); Cat/TFType/Name are
// that same address's parts, kept structured rather than re-parsed from it.
type ImportSpec struct {
	Addr   string
	ID     string
	Cat    string
	TFType string
	Name   string
}

// ResourceAddr is the module-qualified address tofu/terraform accept on the
// command line (import, -target): module.<cat>.<type>.<name>, plus
// ["<key>"] for a for_each instance. The key is quoted, so any character in
// it survives.
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

	// set when this resource is folded into a for_each group (§5.3):
	grp     *fgroup
	grpLead bool   // the one member that actually renders the block
	grpKey  string // this member's for_each map key
}

// refTarget is what an indexed literal value resolves to. key is non-empty
// only when the target is a for_each group member -- then the traversal is
// aws_x.name["key"].attr.
type refTarget struct{ cat, tfType, name, attr, key string }

// freeformIDTypes are resource types whose provider-assigned ID is a
// human-chosen string (a domain name) rather than an opaque AWS-generated
// identifier -- indexing their bare ID as a reference target is unsafe: a
// literal that merely happens to spell the same domain name in a
// completely unrelated resource's own config (an ACM certificate's
// domain_name, a Route53 record's name, a CloudFront distribution's
// aliases, ...) gets silently rewired into a cross-resource/cross-module
// reference it was never meant to be. Confirmed as a real, cycle-causing
// bug: an aws_acm_certificate (module security) and an
// aws_api_gateway_domain_name (module integration) configured with the
// identical domain name -- the ordinary, expected way to use either of
// them -- produced a real dependency cycle (integration legitimately
// depends on security for the cert ARN; the coincidental domain-name
// match then wired security right back to integration, a cycle neither
// direction should exist). Every other resource type's ID in this
// codebase is AWS-assigned and effectively unguessable, so this
// collision risk is specific to "the ID IS the domain name" types, not a
// general problem with ID-based reference matching.
var freeformIDTypes = map[string]bool{"aws_api_gateway_domain_name": true}

// typeNoRefKeys is noRefKeys scoped to specific resource types, for fields
// that are free-form everywhere else but only collide with another
// resource's bare ID for this one type. Confirmed against a real account:
// AWS auto-creates a Cloud Map namespace for ECS Service Connect using the
// cluster's own ID as the namespace's "name" -- a plain display string on
// aws_service_discovery_http_namespace, not a link back to the cluster.
// The ECS cluster legitimately references the namespace by ARN
// (service_connect_defaults.namespace); wiring this coincidental match the
// other way as well produced a real dependency cycle between the two
// modules. private_dns/public_dns namespaces share the same "name"
// semantics and the same auto-creation path, so they're included too.
var typeNoRefKeys = map[string]map[string]bool{
	"aws_service_discovery_http_namespace":        {"name": true},
	"aws_service_discovery_private_dns_namespace": {"name": true},
	"aws_service_discovery_public_dns_namespace":  {"name": true},
}

type outSpec struct {
	trav hcl.Traversal
	// rawExpr, when set, overrides trav: a `for` expression over a whole
	// §5.3 for_each group (see wireValue's grouped-target branch), which
	// hclwrite's traversal-only SetAttributeTraversal can't express.
	rawExpr string
	desc    string
}

// inputSpec is one no-default module variable: either a cross-module wire
// (wireValue) or an external reference the module can't resolve within this
// scan (hoistExternalRefs) -- both are "the root must supply this", just
// with a traversal vs. a literal on the root side.
type inputSpec struct {
	desc string
	typ  string // "string" or "list(string)"
}

// modBuild accumulates one module's files.
type modBuild struct {
	body   *hclwrite.File
	outs   map[string]outSpec   // output name -> value + description
	inputs map[string]inputSpec // no-default variable name -> declaration
	vars   []hoistedVar         // hoisted scalars (with default)
	data   dataUse
	count  int
	// externalRefValues tracks which raw value a bare external-ref variable
	// name (e.g. "vpc_id") is already claimed for, so multiple resources
	// needing the SAME foreign id/arn share one variable instead of each
	// minting their own -- see hoistExternalRefs.
	externalRefValues map[string]any
	varTaken          map[string]bool      // every variable name claimed in this module (hoisted + external-ref), for collision resolution
	needsLambdaZip    bool                 // module has a zip lambda with no recoverable artifact
	regionAliases     map[string]bool      // aliased "aws" provider configs (region != the root default) this module's resources use
	locals            map[string]cty.Value // §5.3 for_each maps, name -> object keyed by instance key
}

// Write lays the hydrated inventory out as a root module that calls one module
// per resource category. Literal ids/ARNs pointing at another resource become
// references, wired through module inputs/outputs when they cross a category.
func Write(inv model.Inventory, outDir string, opt Options) (Result, error) {
	sch, err := tfschema.Load()
	if err != nil {
		return Result{}, err
	}
	res := Result{Dir: outDir}
	defRegion := defaultRegion(inv)
	usedRegions := map[string]string{} // alias -> region, across every module

	// pass 1: emittable items, category, per-category unique names
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
	// how many of each tf type land in each category -- drives the "sole of
	// its type -> `main`" naming rung.
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

	// §5.3: fold runs of >= 3 structurally-identical same-type resources into
	// one for_each block. Members keep their individual names for dedup
	// bookkeeping but only the lead renders; the shared name is claimed
	// through the same per-category namer so it can't collide.
	if !opt.NoForEach {
		// localName dedup: a `locals {}` block is flat within a module,
		// unlike a resource address (type-qualified) -- see fgroup.localName's
		// doc for the real bug this guards against.
		localNames := map[string]map[string]bool{} // cat -> claimed local names
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

	// tags identical on every taggable resource are safe to lift into the
	// root provider's default_tags -- see commonTags' doc for why the
	// criterion has to be this strict.
	common := commonTags(items, sch)

	// pass 2: value -> refTarget. Bare IDs are only unique within a region
	// (e.g. two same-named SNS topics in different regions share an ID); an
	// ambiguous ID must not become a reference target, or a literal that
	// merely matches it gets wired to the wrong resource. ARNs already carry
	// account+region, so they're never ambiguous.
	idx := map[string]refTarget{}
	idARN := map[string]string{} // ID -> the one ARN it's still unambiguously tied to
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
	wires := map[string]map[string]string{}       // destCat -> varName -> "module.srcCat.out"
	rootArgs := map[string]map[string]cty.Value{} // destCat -> varName -> literal value (external refs)

	// pass 3: render every resource into its module
	var unmanagedList []unmanaged
	for _, it := range items {
		// §5.3: only the group lead renders; every member still gets its own
		// import block, handled in the imports pass below.
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

		// aws_lambda_function / _layer_version must carry a code source. The
		// artifact is not recoverable from the API, so point at a placeholder
		// the module ships; the user swaps in the real build (or ignore_changes).
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
		// A resource outside the root provider's region needs an explicitly
		// aliased "aws" provider instance pinned to its own region: the
		// AWS provider's per-resource `region` attribute isn't consulted
		// during the initial `ImportResourceState` call (only the provider's
		// own configured region is, since no resource config exists yet at
		// that point), so it silently 404s importing anything outside the
		// default region even when `region` is set in the generated config.
		// A provider alias is resolved statically, before any RPC, so it
		// works for import as well as every ordinary read/write.
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

	// write module trees
	cats := make([]string, 0, len(mods))
	for c := range mods {
		cats = append(cats, c)
	}
	sort.Strings(cats)

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

	// root: versions.tf, providers.tf, main.tf, imports.tf, backend.tf, README.md
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
		id := importID(it.r)
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

// noRefKeys are attribute names whose value must never be swapped for a
// cross-resource reference, even when it textually matches another
// resource's bare id or ARN:
//
//   - "dimensions" (map(string)): CloudWatch metric dimensions
//     (aws_cloudwatch_metric_alarm.dimensions and its nested
//     metric_query.metric.dimensions, aws_cloudwatch_log_metric_filter's
//     metric_transformation.dimensions, aws_autoscalingplans_scaling_plan's
//     customized_*_metric_specification.dimensions) are free-form
//     name/value pairs defined by the metric itself, not by Terraform's
//     resource graph.
//   - "task_definition" (string, aws_ecs_service/aws_ecs_task_set): AWS's
//     real API returns this in "family:revision" form, and a real
//     service's Read stores exactly that -- not the task definition's ARN.
//     Wiring it as a reference resolves through aws_ecs_task_definition's
//     `id` (which IS the ARN, per that resource's own schema), producing a
//     value that doesn't match what Read actually persists. Confirmed
//     against a real account: the literal hydrated value is already
//     correct as-is.
//   - "name": a resource's own name is an identity LABEL, chosen
//     independently by whoever created it -- never a pointer into
//     Terraform's resource graph, even on the rare occasion its value
//     happens to equal some other resource's bare id. Confirmed as a real,
//     recurring collision class, not a one-off: typeNoRefKeys already
//     carried a narrower version of this fix for Cloud Map namespaces
//     (AWS auto-creates one using the ECS cluster's own id as the
//     namespace's "name"); a second, unrelated case turned up in a real
//     account's data on its own -- an aws_security_group named "tailnet",
//     the same literal string as an aws_ecs_cluster's id, an ordinary
//     naming coincidence with no AWS-level cause at all -- and got wired
//     to that cluster's id instead of staying the security group's own
//     literal name. Two independent real occurrences of "some resource's
//     name coincidentally equals another resource's id" is exactly what
//     "name" always risks, not particular to Cloud Map or ECS clusters;
//     excluding it globally is the general fix, not another special case.
//     A resource's OWN name is never how Terraform's graph is meant to be
//     expressed (real cross-references use dedicated attributes -- vpc_id,
//     cluster, security_group_id -- never "name"), so this closes the
//     whole class rather than the next instance of it.
//   - "tags" (map(string), every taggable resource): free-form user
//     metadata, exactly like "dimensions" above, and exposed to the exact
//     same collision as "name" -- confirmed in the SAME real account's
//     data as the "name" case: the security group in question also
//     carried a "Name" tag (the ordinary AWS convention of mirroring a
//     resource's own name into its Name tag) whose value was ALSO
//     "tailnet", and that -- a tag VALUE, not the resource's own "name"
//     attribute -- wired to the same cluster id too, surviving the "name"
//     fix untouched since it's a different key nested one level deeper.
//     Tag keys/values are chosen independently by whoever tagged the
//     resource, never a pointer into Terraform's graph, so the whole map
//     is excluded rather than guessing which conventional tag key (Name,
//     Environment, ...) might coincidentally collide next.
var noRefKeys = map[string]bool{"dimensions": true, "task_definition": true, "name": true, "tags": true}

// wireValue walks a config value, turning literals that match another resource
// into references. Same-category matches become direct traversals; cross-category
// matches register a module output + input + root wire and become var refs.
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
			// §5.3 for_each group member, referenced from another category:
			// share ONE output (a `for` map over the whole group, keyed the
			// same way the group's own `local` already is) and one input
			// across every member of this group that ends up wired, rather
			// than minting a separate single-key output per referenced
			// member. Confirmed against a real account: without this, three
			// subnets in one for_each group produced three near-identical
			// outputs (public_10_1_252_0_24_id, _253_, _254_), each a
			// hardcoded single-key traversal -- exactly the duplication §5.3
			// already collapses on the locals side.
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
				// see noRefKeys' / typeNoRefKeys' doc: this key's value must
				// stay exactly as hydrated, never swapped for a
				// cross-resource reference.
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
		// pinned to the same aliased provider as the resources it parameterizes,
		// or it would resolve via the module's default (unaliased) region instead.
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

// versionsFile writes the root terraform{}/required_providers block, kept
// separate from providersFile per the standard module layout (versions.tf:
// version constraints; providers.tf: actual provider configuration).
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

// providersFile writes the root provider blocks: the default (unaliased)
// provider plus one aliased "aws" provider per non-default region actually
// used by a generated resource (alias -> region). defaultTags, when
// non-empty, is written as a default_tags block on every provider instance
// (default_tags is a per-provider-config setting, so an aliased region's
// provider needs its own copy to actually apply it).
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

// commonTags returns the tag key/value pairs identical on every taggable
// resource being emitted (schema has a "tags" attribute) -- the only set
// safe to lift into the provider's default_tags without risking a plan
// diff on any individual resource. default_tags applies unconditionally to
// every taggable resource once set, with no per-resource opt-out; anything
// short of "every single one already has this exact value" would add or
// change a real resource's effective tags the moment it's introduced. A
// taggable resource with no tags at all (or a different value) evicts the
// key entirely, rather than being left out of consideration.
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

// stripCommonTags removes from a resource's own "tags" map any key already
// hoisted into the provider's default_tags: default_tags merges into every
// resource's effective tags automatically, so repeating an identical entry
// in the resource itself is redundant. A resource with tag(s) beyond the
// common set keeps just those; a resource whose tags are now empty drops
// the attribute entirely rather than emitting `tags = {}`.
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

// moduleVersionsFile declares the aliased "aws" provider configs a module
// requires from its caller (paired with the `providers = {...}` argument
// rootMainFile adds to that module's block). Modules never configure a
// provider themselves, only declare the requirement -- so this is always
// versions.tf, never providers.tf.
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

// rawExprTokens parses a fragment of HCL as the right-hand side of an
// assignment and returns its expression tokens, for constructs cty.Value
// can't represent (bare traversals as object keys/values -- provider
// references, `configuration_aliases`).
func rawExprTokens(src string) hclwrite.Tokens {
	f, diags := hclwrite.ParseConfig([]byte("x = "+src), "generated.tf", hcl.InitialPos)
	if diags.HasErrors() {
		// src is always our own construction from sanitized identifiers; a
		// parse failure here is a bug in the caller, not bad input data.
		panic("rawExprTokens: " + diags.Error())
	}
	return f.Body().GetAttribute("x").Expr().BuildTokens(nil)
}

// writeBlock renders a config map into an hcl body per the schema block:
// map-typed args as `k = {}`, nested block types as `k {}`, refs as bare
// traversals, everything else as a plain attribute.
func writeBlock(body *hclwrite.Body, cfg map[string]any, block *tfschema.Block) {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := cfg[k]

		// a nested block type: aws models it as `k { ... }` (repeatable)
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
		// Attributes the provider models as `set(object(...))` / `list(object(...))`
		// (SDKv2 ConfigMode "attr" blocks, e.g. aws_route_table.route) reject a
		// partial object literal: every sub-attribute must be present. Pad the
		// missing ones with null.
		if names := objectAttrNames(attr); names != nil {
			v = padObjects(v, names)
		}
		if tk := valueTokens(v, typ); tk != nil {
			body.SetAttributeRaw(k, tk)
		}
	}
}

// nullTok renders as the bare keyword `null`.
type nullTok struct{}

// lambdaPlaceholderZip is the stand-in deployment artifact shipped in any module
// that has a zip-package lambda (the real artifact is not recoverable from AWS).
const lambdaPlaceholderZip = "lambda_placeholder.zip"

// emptyZip is a valid empty ZIP archive (end-of-central-directory record only).
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

// objectAttrNames returns the attribute names of the object an attribute is a
// collection of (or a single nested object of), or nil if it isn't one.
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

// padObjects fills every name not already set in each object with null.
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

// valueTokens renders a config value (including refs at any depth) as HCL
// expression tokens. Returns nil for empty values.
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
		// empty strings that reach here were set deliberately by a hydrator
		// (hydrate.Generic already prunes empties); emit them.
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

// templateTokens renders a tmpl as a quoted HCL template string with embedded
// ${...} interpolations. hclwrite.TokensForValue would escape the ${, so this
// hand-builds the token stream.
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

// --- references -------------------------------------------------------

// ref is a config value that should render as a bare HCL traversal
// (aws_vpc.main.id) rather than a quoted string.
type ref struct{ trav hcl.Traversal }

func rootName(t hcl.Traversal) string {
	if len(t) < 2 {
		return ""
	}
	root, _ := t[0].(hcl.TraverseRoot)
	attr, _ := t[1].(hcl.TraverseAttr)
	return root.Name + "." + attr.Name
}

// --- import ids ------------------------------------------------------

// importID returns the value `terraform import <addr> <id>` expects.
// idRefAttr is the attribute other resources use to reference this one by its
// discovered ID. Usually "id", but a few resources expose that value under a
// different name (e.g. aws_db_instance.id is the DBI resource id, while other
// resources reference the instance by its identifier).
func idRefAttr(tfType string) string {
	switch tfType {
	case "aws_db_instance":
		return "identifier"
	default:
		return "id"
	}
}

// noImportTypes are real, fully-configurable resource types the provider
// itself has never wired an Importer for at all (no classic
// schema.ResourceImporter, no newer @ArnIdentity/@IdentityAttribute
// passthrough) -- `terraform import`/`--fast-import` fails outright for
// any resource of these types with "doesn't support import", confirmed
// against a real account rather than assumed, and by reading the real
// provider source (neither guardduty/detector_feature.go nor
// guardduty/organization_configuration_feature.go declares an Importer).
// This is a genuine, structural provider limitation, not a hydrator bug:
// the resource's config is still emitted normally (correctly describing
// the real, already-enabled feature state), just without a matching
// import{} block -- so `tofu apply` on a fresh project creates/re-PUTs
// this specific resource once (a safe, idempotent PutXFeature call that
// converges to the same state already in place, not a destructive
// create) rather than adopting existing state the way every other
// resource in the project does.
var noImportTypes = map[string]bool{
	"aws_guardduty_detector_feature":                   true,
	"aws_guardduty_organization_configuration_feature": true,
}

func importID(r model.Resource) string {
	if noImportTypes[r.TFType] {
		return ""
	}
	if r.ImportID != "" {
		return r.ImportID
	}
	switch r.TFType {
	case "aws_iam_policy", "aws_sns_topic",
		"aws_resourceexplorer2_index", "aws_resourceexplorer2_view",
		"aws_iam_openid_connect_provider", "aws_iam_saml_provider",
		"aws_secretsmanager_secret", "aws_lb", "aws_lb_target_group",
		"aws_lb_listener", "aws_acm_certificate", "aws_ecs_task_definition",
		"aws_sfn_activity", "aws_sfn_state_machine", "aws_lambda_code_signing_config":
		// the bare ID (the ARN's trailing segment(s), or for a cert just the
		// UUID) isn't a valid import id on its own for these types -- the
		// provider's own import logic parses it as an ARN and fails loudly
		// ("could not parse import ID ... as ARN") otherwise, confirmed
		// against a real account. aws_ecs_task_definition is the odd one
		// out here: r.ID ("family:revision") is the documented *legacy*
		// import format and looks completely valid, but the provider
		// changed this resource's import id to require the full ARN in a
		// later version -- with no fallback, so the bare family:revision
		// string hits the same "arn: invalid prefix" failure as the
		// others, just with zero diagnostic context since it fails deep
		// inside the provider's own ARN-detection path rather than a
		// user-facing validation.
		return r.ARN
	case "aws_sqs_queue":
		if r.Region != "" && r.Account != "" {
			return fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", r.Region, r.Account, r.ID)
		}
		return ""
	case "aws_cloudformation_stack":
		// ARN id is "<name>/<uuid>"; the provider imports by name.
		if n, _, ok := strings.Cut(r.ID, "/"); ok {
			return n
		}
		return r.ID
	case "aws_cloudformation_stack_set":
		// ARN id is "<name>:<uuid>"; import is by name.
		if n, _, ok := strings.Cut(r.ID, ":"); ok {
			return n
		}
		return r.ID
	case "aws_ssm_parameter":
		// r.ID is the ARN's resource segment, which never carries a
		// hierarchical parameter's real leading "/". hydrateSSMParameter
		// already resolved and confirmed the true name (trying both forms
		// against the live API) and put it in Config; prefer that over
		// re-guessing here.
		if name, ok := r.Config["name"].(string); ok && name != "" {
			return name
		}
		return r.ID
	case "aws_key_pair":
		// r.ID (from the ARN) is the key pair id (key-xxxx); the provider
		// imports by key_name instead -- confirmed against a real account
		// ("Cannot import non-existent remote object" using the bare id).
		if name, ok := r.Config["key_name"].(string); ok && name != "" {
			return name
		}
		return r.ID
	case "aws_service_discovery_private_dns_namespace":
		// import id is "NAMESPACE_ID:VPC_ID" -- confirmed against a real
		// account ("Unexpected format of ID ... expected NAMESPACE_ID:VPC_ID")
		// and the real provider source's own Importer. hydrateSDNamespace
		// already recovered the vpc (via the namespace's own Route53 zone,
		// since Cloud Map's own API never reads it back) and put it in
		// Config, so it's available here the same way aws_ssm_parameter's
		// case above reuses its hydrator's own resolved name.
		if vpc, ok := r.Config["vpc"].(string); ok && vpc != "" {
			return r.ID + ":" + vpc
		}
		return r.ID
	default:
		return r.ID
	}
}

// --- logical names ------------------------------------------------------

var nameSanitize = regexp.MustCompile(`[^A-Za-z0-9_]+`)

// maxLogicalName caps a resource's logical name. Anything longer is truncated
// with a short hash suffix so it stays unique and legible.
const maxLogicalName = 48

// opaqueIDTypes are resource types whose AWS-assigned id carries no
// human-chosen name at all -- unlike, say, an IAM role or Lambda function
// whose id/ARN trailing segment IS its name (lastNameSegment recovers that),
// these core EC2 networking primitives are only ever identified by a
// system-generated id. When nothing better is available (no Name tag, no
// heuristic, no descriptive `name` attribute) they get `<prefix>_<hash>` --
// deterministic and stable, ugly but never misleading. Never `sg_01`.
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

// claim resolves a resource's local name by walking a fixed ladder (see
// rawName), then de-duplicates with a numeric suffix. Dedup is scoped per
// (type, name) -- a Terraform address is <type>.<name>, so aws_vpc.main and
// aws_subnet.main don't collide, and both can be "main".
func (n *namer) claim(r model.Resource, sole bool) string {
	base := sanitizeName(rawName(r, sole))
	name := base
	for i := 2; n.used[r.TFType+"."+name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	n.used[r.TFType+"."+name] = true
	return name
}

// rawName is the naming ladder: sole of its type -> a "Name" tag -> an
// attribute/description heuristic -> a type-specific id extraction -> a
// descriptive `name` attribute -> a deterministic hash (opaque-id types) or
// the id's trailing segment.
func rawName(r model.Resource, sole bool) string {
	if sole {
		return "main"
	}
	// A "Name" tag counts -- unless it's itself a lazy enumeration
	// (sg-1, subnet_02, vpc 3), in which case a purpose heuristic beats it.
	if v := r.Tags["Name"]; v != "" && !lazyEnumeration(v) {
		return v
	}
	if h := heuristicName(r); h != "" {
		return h
	}
	if v := r.Tags["Name"]; v != "" {
		return v // a lazy-enumeration tag, but nothing better turned up
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

// heuristicName infers a purpose-based name from a resource's own config for
// the handful of types where that's both common and useful. Returns "" when
// nothing matches. Deliberately small and conservative -- the LLM fallback
// (spec §5.2) covers the long tail.
func heuristicName(r model.Resource) string {
	switch r.TFType {
	case "aws_security_group":
		// rules are separate resources in this project's output, so the
		// signal is the SG's own name + description text.
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

// wellKnownPorts maps a single TCP/UDP port to a short service label, so a
// standalone SG rule reads as `ingress_https` rather than `sgr_0abc…`.
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

// sgRuleName derives a purpose name for a standalone security-group rule from
// its direction, protocol and port(s): ingress_https, egress_all,
// ingress_5000, ingress_8000_9000, ingress_icmp.
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

// cfgInt reads a config number (JSON round-trips these as float64) as an int.
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

// lazyEnumerationRe matches names like "sg1", "sg-1", "subnet_02", "vpc 3" --
// a short alpha prefix and a small number, i.e. someone counted instead of
// naming.
var lazyEnumerationRe = regexp.MustCompile(`(?i)^[a-z]{1,8}[-_ ]?\d{1,3}$`)

func lazyEnumeration(s string) bool { return lazyEnumerationRe.MatchString(s) }

// looksLikeAWSID reports whether s is a bare AWS resource id
// (vpc-…, sg-…, subnet-…, rtb-…) rather than a human name.
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

// lastNameSegment reduces an ARN / URL / path-style id to its trailing
// human-meaningful part, e.g.
//
//	arn:aws:sns:us-west-1:123:aws-controltower-Notifications -> aws-controltower-Notifications
//	arn:aws:iam::123:role/service-role/MyRole                -> MyRole
//	https://sqs.us-west-1.amazonaws.com/123/my-queue         -> my-queue
//
// Plain ids (vpc-0abc, my-function) pass through untouched.
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

// shortHash is a stable 8-hex-char digest, for disambiguating truncated names.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

func isAlpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
