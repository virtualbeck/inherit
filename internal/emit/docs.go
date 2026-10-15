package emit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/virtualbeck/inherit/model"
)

// rootReadme describes the generated project.
func rootReadme(inv model.Inventory, mods map[string]*modBuild, blocks int, defaultTags map[string]string) string {
	cats := make([]string, 0, len(mods))
	for c := range mods {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s infrastructure\n\n", inv.Account)
	fmt.Fprintf(&b, "%d resources across %d modules, in %s.\n\n", blocks, len(cats), strings.Join(inv.Regions, ", "))

	b.WriteString("## Layout\n\n")
	b.WriteString("```\n")
	b.WriteString("versions.tf    terraform{} block: required OpenTofu/provider versions\n")
	b.WriteString("providers.tf   the aws provider (plus one aliased per extra region)\n")
	b.WriteString("main.tf        the composition root: every module, wired together\n")
	b.WriteString("imports.tf     one import {} per resource (see below)\n")
	b.WriteString("backend.tf     local state by default; a commented S3 skeleton\n")
	b.WriteString("modules/<name>/  one module per resource category\n")
	b.WriteString("```\n\n")
	b.WriteString("The module tree is flat (one level), following the OpenTofu standard\n")
	b.WriteString("structure. Modules do not look anything up: a value one module needs\n")
	b.WriteString("from another is an `output` there, a `variable` here, and an argument in\n")
	b.WriteString("`main.tf`.\n\n")

	fmt.Fprintf(&b, "Modules: %s\n\n", strings.Join(cats, ", "))

	b.WriteString("## Adopting this into state\n\n")
	b.WriteString("Nothing here touches the account. To bring the resources under management:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("tofu init\n")
	b.WriteString("tofu validate\n")
	b.WriteString("tofu plan          # shows what import {} would bring in\n")
	b.WriteString("```\n\n")
	b.WriteString("`inherit import` runs `tofu import` per resource, which only writes local\n")
	b.WriteString("state (`inherit fast-import` does the same job much faster on a large\n")
	b.WriteString("account). Then iterate on the HCL until `tofu plan` is clean, commit, and\n")
	b.WriteString("delete `imports.tf`.\n\n")
	b.WriteString("## Before you rely on it\n\n")
	b.WriteString("- Hoisted names live in each module's `variables.tf` as defaults; change\n")
	b.WriteString("  them there, not in `main.tf`.\n")
	if len(defaultTags) > 0 {
		b.WriteString("- A tag identical on every taggable resource was lifted into the root\n")
		b.WriteString("  provider's `default_tags` and dropped from each resource's own `tags`;\n")
		b.WriteString("  it still applies everywhere, just from one place.\n")
	}
	b.WriteString("- Region and account id inside ARNs were replaced with `data` lookups.\n")
	b.WriteString("- Some attributes are best-effort. Review the plan before applying.\n")
	return b.String()
}

func moduleReadme(cat string, m *modBuild) string {
	var types []string
	seen := map[string]bool{}
	// crude: pull `resource "type"` lines from the rendered body
	for line := range strings.SplitSeq(string(m.body.Bytes()), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `resource "`) {
			t := strings.SplitN(line, `"`, 3)[1]
			if !seen[t] {
				seen[t] = true
				types = append(types, t)
			}
		}
	}
	sort.Strings(types)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", cat)
	fmt.Fprintf(&b, "Internal decomposition of the account's %s resources. Not a reusable\n", cat)
	b.WriteString("module: it is instantiated once, by the root `main.tf`.\n\n")
	if len(types) > 0 {
		b.WriteString("Resource types:\n\n")
		for _, t := range types {
			fmt.Fprintf(&b, "- `%s`\n", t)
		}
	}
	return b.String()
}

// backendTF returns the commented S3-backend skeleton, with its example
// state key namespaced by account, and by environment too when the caller
// supplied one (internal/cli always does; a direct emit.Write caller with an
// empty Environment gets the flat, account-only key instead).
func backendTF(account, environment string) string {
	key := account + "/terraform.tfstate"
	if environment != "" {
		key = account + "/" + environment + "/terraform.tfstate"
	}
	return `# State is local by default (terraform.tfstate next to this file).
#
# To use S3 + a lock table instead, create them, uncomment, and run
#   tofu init -migrate-state
#
# terraform {
#   backend "s3" {
#     bucket       = "my-tofu-state"
#     key          = "` + key + `"
#     region       = "us-east-1"
#     use_lockfile = true
#     encrypt      = true
#   }
# }
`
}
