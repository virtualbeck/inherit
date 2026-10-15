package emit

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// WriteImportOverrides writes one `lifecycle { ignore_changes = all }` stub
// per import-covered resource, grouped one file (import_override.tf) per
// category module. Terraform merges an override file's resource block onto
// the "real" one already defined elsewhere in the same directory -- verified
// against a real `tofu plan`: a resource whose main.tf body has drifted
// completely from its actual state shows "No changes" once this merges in,
// because ignore_changes = all excludes every attribute from the diff.
//
// These files are meant to be written immediately before, and removed
// immediately after, a bulk-import apply (see the --fast-import CLI flow).
// They must never be left in the generated project: as long as they're
// present, ANY future `plan`/`apply` -- not just the bulk-import one -- would
// silently stop reporting real drift for every resource they cover.
//
// Returns the file paths written, so the caller can remove exactly those
// files afterward regardless of success or failure. On error nothing is left
// behind: any file already written is removed before returning.
//
// A for_each group gets one override block, not one per instance: the block
// addresses the resource, and ignore_changes applies to every instance.
func WriteImportOverrides(outDir string, imports []ImportSpec) (paths []string, err error) {
	defer func() {
		if err != nil {
			RemoveImportOverrides(paths)
			paths = nil
		}
	}()

	byCat := map[string][]ImportSpec{}
	seen := map[[3]string]bool{}
	for _, s := range imports {
		k := [3]string{s.Cat, s.TFType, s.Name}
		if seen[k] {
			continue
		}
		seen[k] = true
		byCat[s.Cat] = append(byCat[s.Cat], s)
	}

	cats := make([]string, 0, len(byCat))
	for cat := range byCat {
		cats = append(cats, cat)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		specs := byCat[cat]
		sort.Slice(specs, func(i, j int) bool {
			if specs[i].TFType != specs[j].TFType {
				return specs[i].TFType < specs[j].TFType
			}
			return specs[i].Name < specs[j].Name
		})

		f := hclwrite.NewEmptyFile()
		for _, s := range specs {
			b := f.Body().AppendNewBlock("resource", []string{s.TFType, s.Name}).Body()
			lc := b.AppendNewBlock("lifecycle", nil).Body()
			lc.SetAttributeRaw("ignore_changes", hclwrite.TokensForIdentifier("all"))
			f.Body().AppendNewline()
		}

		path := filepath.Join(outDir, "modules", cat, "import_override.tf")
		if err = os.WriteFile(path, f.Bytes(), 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// RemoveImportOverrides deletes the files WriteImportOverrides wrote. Missing
// files are not an error -- this is called unconditionally on cleanup.
func RemoveImportOverrides(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}
