package emit

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// Transient ignore_changes = all; never leave these behind.
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

func RemoveImportOverrides(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}
