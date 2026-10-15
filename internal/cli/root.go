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
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

	// Ctrl-C / SIGTERM cancel the context instead of killing the process, so
	// deferred cleanup runs -- above all import --fast removing its
	// ignore_changes = all override files -- and tofu is interrupted
	// gracefully (internal/tf). A second signal, once the first has
	// cancelled, falls through to the default: exit immediately.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	err := root.ExecuteContext(ctx)
	stop()
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("interrupted: %w", err)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// confirm asks a yes/no question on stderr, defaulting to no. Cancelling ctx
// (Ctrl-C) answers no rather than leaving the read blocked.
func confirm(ctx context.Context, prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	type answer struct {
		line string
		err  error
	}
	ch := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		ch <- answer{line, err}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr)
		return false, ctx.Err()
	case a := <-ch:
		if a.err != nil {
			return false, a.err
		}
		line := strings.ToLower(strings.TrimSpace(a.line))
		return line == "y" || line == "yes", nil
	}
}
