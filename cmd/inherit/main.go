// Command inherit discovers a live AWS account (read-only) and writes a flat
// inventory.json describing what's there. That file is the input to the
// inherit backend, which turns it into a working OpenTofu/Terraform project.
//
// This tool only ever calls read-only AWS APIs (a signing-time guard rejects
// anything else) plus, on `inherit submit`, a single upload of the redacted
// inventory to the backend. `inherit scan` makes no network calls except to
// AWS.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/virtualbeck/inherit-core/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "inherit",
		Short:         "Discover a live AWS account and write inventory.json (read-only)",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("inherit {{.Version}}\n")
	root.AddCommand(scanCmd(), submitCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
