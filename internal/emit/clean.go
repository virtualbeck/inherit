package emit

import (
	"os"
	"path/filepath"
	"strings"
)

// Every file Write may put in a module directory.
var moduleFiles = []string{
	"main.tf", "locals.tf", "variables.tf", "outputs.tf", "data.tf",
	"versions.tf", "README.md", lambdaPlaceholderZip, importOverrideFile,
}

// Marks a module README as ours.
const moduleReadmeMarker = "Internal decomposition of the account's"

// removeStale deletes files a previous Write left; keeps user files.
func removeStale(outDir string) error {
	if err := removeIfExists(filepath.Join(outDir, "UNMANAGED_FIELDS.md")); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(outDir, "modules"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		dir := filepath.Join(outDir, "modules", e.Name())
		if !e.IsDir() || !generatedModule(dir) {
			continue
		}
		for _, f := range moduleFiles {
			if err := removeIfExists(filepath.Join(dir, f)); err != nil {
				return err
			}
		}
		_ = os.Remove(dir) // only succeeds if now empty
	}
	return nil
}

func generatedModule(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "README.md"))
	return err == nil && strings.Contains(string(b), moduleReadmeMarker)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
