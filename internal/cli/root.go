// Package cli wires the inherit command:
//
//	inherit scan       discover the account (read-only) and generate the project
//	inherit generate   regenerate the project from an existing inventory.json
//	inherit plan       tofu init + validate + plan against a generated project
//	inherit import     plan, plus state-only import of every resource
//
// The only network calls inherit itself makes are read-only AWS APIs during
// scan (a signing-time guard rejects anything else). plan/import shell out
// to tofu/terraform, which uses your credentials to read -- classic import
// calls nothing but the provider's Read, and --fast only ever applies a plan
// it has verified contains nothing but no-op imports.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/virtualbeck/inherit/internal/version"
)

// Execute is the entry point.
func Execute() {
	root := &cobra.Command{
		Use:           "inherit",
		Short:         "Turn a live, non-IaC AWS account into a working OpenTofu/Terraform project",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("inherit {{.Version}}\n")
	root.AddCommand(scanCmd(), generateCmd(), planCmd(), importCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}
