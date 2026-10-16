// Package cli wires the inherit commands.
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

	// Signals cancel ctx so cleanup runs; repeat exits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	err := root.ExecuteContext(ctx)
	interrupted := ctx.Err() != nil // read before stop(), which cancels ctx
	stop()
	if err != nil {
		if interrupted {
			err = fmt.Errorf("interrupted: %w", err)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// confirm defaults to no; Ctrl-C also answers no.
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
