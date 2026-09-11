package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/virtualbeck/inherit/internal/awsx"
	"github.com/virtualbeck/inherit/internal/discover"
	"github.com/virtualbeck/inherit/internal/hydrate"
	"github.com/virtualbeck/inherit/internal/prune"
	"github.com/virtualbeck/inherit/internal/redact"
	"github.com/virtualbeck/inherit/internal/version"
)

const scanConcurrency = 8

func scanCmd() *cobra.Command {
	var (
		profile          string
		regions          []string
		out              string
		servicesExclude  []string
		servicesInclude  []string
		includeEphemeral bool
		includeDefaults  bool
		debug            bool
		yes              bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover the account and write inventory.json (+ inventory.secrets.json, local only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			cfg, err := awsx.Load(ctx, firstNonEmpty(regions), profile)
			if err != nil {
				return err
			}
			id, err := awsx.ResolveIdentity(ctx, cfg)
			if err != nil {
				return err
			}
			explicitRegions := len(regions) > 0
			if len(regions) == 0 {
				regions, err = awsx.EnabledRegions(ctx, cfg)
				if err != nil {
					return err
				}
			}
			if out == "" {
				out = "inherit-" + id.Account
			}
			absOut, _ := filepath.Abs(out)

			fmt.Fprintln(os.Stderr, "inherit scan will run read-only against:")
			fmt.Fprintf(os.Stderr, "  account    %s\n", id.Account)
			fmt.Fprintf(os.Stderr, "  identity   %s\n", id.ARN)
			if profile != "" {
				fmt.Fprintf(os.Stderr, "  profile    %s\n", profile)
			}
			fmt.Fprintf(os.Stderr, "  regions    %s\n", strings.Join(regions, ", "))
			fmt.Fprintf(os.Stderr, "  output     %s\n\n", absOut)

			if !yes {
				ok, err := confirm("Proceed? [y/N] ")
				if err != nil {
					return err
				}
				if !ok {
					fmt.Fprintln(os.Stderr, "aborted.")
					return nil
				}
			}

			fmt.Fprintln(os.Stderr, "discovering ...")
			inv, ephem, excl, err := discover.Sweep(ctx, cfg, discover.Options{
				Account:          id.Account,
				Partition:        id.Partition,
				Regions:          regions,
				Concurrency:      scanConcurrency,
				IncludeEphemeral: includeEphemeral,
				Exclude:          servicesExclude,
				Services:         servicesInclude,
				OnRegion: func(region string, found int, err error) {
					switch {
					case err != nil:
						fmt.Fprintf(os.Stderr, "  ! %-16s %v\n", region, err)
					case debug || found > 0:
						fmt.Fprintf(os.Stderr, "  %-16s %d\n", region, found)
					}
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "\nfound %d resources across %d regions", len(inv.Resources), len(regions))
			if ephem > 0 {
				fmt.Fprintf(os.Stderr, " (%d ephemeral skipped)", ephem)
			}
			if excl > 0 {
				fmt.Fprintf(os.Stderr, " (%d excluded)", excl)
			}
			fmt.Fprintln(os.Stderr)

			fmt.Fprintln(os.Stderr, "hydrating ...")
			st, err := hydrate.Run(ctx, cfg, &inv, hydrate.Options{})
			if err != nil {
				return err
			}
			inv.ToolVersion = version.String()
			fmt.Fprintf(os.Stderr, "  %d hydrated, %d awaiting a hydrator, %d unmapped types\n",
				st.Hydrated, sum(st.NoHydrator), len(st.Unmapped))
			if debug {
				for _, e := range st.Errors {
					fmt.Fprintf(os.Stderr, "  ! %v\n", e)
				}
			}

			pr := prune.Noise(&inv, prune.Options{
				IncludeDefaults: includeDefaults,
				KeepAllRegions:  explicitRegions,
			})
			if !pr.Empty() {
				fmt.Fprintf(os.Stderr, "  pruned %d default + %d singleton resources", pr.Defaults, pr.Singletons)
				if len(pr.Regions) > 0 {
					fmt.Fprintf(os.Stderr, "; %d regions with nothing in use dropped (%s)", len(pr.Regions), strings.Join(pr.Regions, ", "))
				}
				fmt.Fprintf(os.Stderr, "\n  %d resources across %d regions kept (--include-defaults to keep everything)\n",
					len(inv.Resources), len(inv.Regions))
			}

			secrets := redact.Split(&inv)

			if err := os.MkdirAll(absOut, 0o755); err != nil {
				return err
			}
			invPath := filepath.Join(absOut, "inventory.json")
			if err := writeJSON(invPath, inv, 0o644); err != nil {
				return err
			}
			secPath := filepath.Join(absOut, "inventory.secrets.json")
			if err := writeJSON(secPath, secrets, 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(absOut, ".gitignore"), []byte("inventory.secrets.json\n"), 0o644); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "\nwrote %s\n", invPath)
			if len(secrets) > 0 {
				fmt.Fprintf(os.Stderr, "wrote %s  (%d values redacted from inventory.json; stays local, never uploaded)\n", secPath, len(secrets))
			}
			fmt.Fprintf(os.Stderr, "\nnext: inherit submit --out %s\n", absOut)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&profile, "profile", "", "AWS profile (default: AWS_PROFILE, then \"default\")")
	f.StringSliceVar(&regions, "regions", nil, "regions to scan (default: all enabled)")
	f.StringVarP(&out, "out", "o", "", "output directory (default: ./inherit-<account>)")
	f.StringSliceVar(&servicesExclude, "services-exclude", nil, "AWS services or service:type to skip")
	f.StringSliceVar(&servicesInclude, "services-include", nil, "scan ONLY these AWS services")
	f.BoolVar(&includeEphemeral, "include-ephemeral", false, "keep snapshots / AMIs / backups (skipped by default)")
	f.BoolVar(&includeDefaults, "include-defaults", false, "keep AWS-created default VPCs/SGs and per-region setting singletons, and every region (pruned by default)")
	f.BoolVar(&debug, "debug", false, "verbose diagnostics")
	f.BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}
