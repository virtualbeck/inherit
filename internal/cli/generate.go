package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/virtualbeck/inherit/internal/emit"
	"github.com/virtualbeck/inherit/model"
)

const (
	inventoryFile = "inventory.json"
	secretsFile   = "inventory.secrets.json"
)

// gitignore keeps everything that can carry a live secret or is purely
// local working state out of the generated project's history: the redacted
// values, tofu's state/plan files (import writes real attribute values,
// secrets included, into terraform.tfstate), and what an interrupted
// `import --fast` could leave behind (an override hiding all drift, and its
// plan scratch directory).
const gitignore = `inventory.secrets.json
.terraform/
*.tfstate
*.tfstate.*
*.tfplan
crash.log
import_override.tf
.fastimport-*/
`

func writeGitignore(dir string) error {
	return os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0o644)
}

// genFlags are the emit options shared by scan and generate.
type genFlags struct {
	environment string
	forEach     bool
}

func (g *genFlags) register(f *pflag.FlagSet) {
	f.StringVarP(&g.environment, "environment", "e", "", "label for the example state key in backend.tf (e.g. dev, prod)")
	f.BoolVar(&g.forEach, "for-each", true, "fold runs of 3+ identical resources into one for_each block (--for-each=false to disable)")
}

func generateCmd() *cobra.Command {
	var gen genFlags
	cmd := &cobra.Command{
		Use:   "generate [dir]",
		Short: "Regenerate the project from the inventory.json in dir (offline, no AWS calls)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dir, _ := filepath.Abs(dirArg(args))
			inv, err := readInventory(dir)
			if err != nil {
				return err
			}
			if inv.ToolVersion != "" {
				fmt.Fprintf(os.Stderr, "inventory from inherit %s: %d resources, account %s\n",
					inv.ToolVersion, len(inv.Resources), inv.Account)
			}
			return generate(inv, dir, gen)
		},
	}
	gen.register(cmd.Flags())
	return cmd
}

// generate writes the project for inv into dir, alongside its inventory.
func generate(inv model.Inventory, dir string, g genFlags) error {
	fmt.Fprintln(os.Stderr, "generating ...")
	er, err := emit.Write(inv, dir, emit.Options{
		Environment: strings.ToLower(strings.TrimSpace(g.environment)),
		NoForEach:   !g.forEach,
	})
	if err != nil {
		return err
	}
	if err := writeGitignore(dir); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  %d resources across %d modules (%s), %d import blocks\n",
		er.Blocks, len(er.Modules), strings.Join(er.Modules, ", "), len(er.Imports))
	if er.Skipped > 0 {
		fmt.Fprintf(os.Stderr, "  %d resources skipped (type not in the bundled provider schema)\n", er.Skipped)
	}
	if er.Unmanaged > 0 {
		fmt.Fprintf(os.Stderr, "  %d attributes left unmanaged (redacted secrets; see UNMANAGED_FIELDS.md)\n", er.Unmanaged)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", dir)
	return nil
}

func readInventory(dir string) (model.Inventory, error) {
	var inv model.Inventory
	path := filepath.Join(dir, inventoryFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return inv, fmt.Errorf("reading %s (run `inherit scan` first): %w", path, err)
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		return inv, fmt.Errorf("parsing %s: %w", path, err)
	}
	return inv, nil
}

func dirArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "."
}
