package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func submitCmd() *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Package inventory.json into inventory.tar.gz",
		Long: "Package inventory.json into inventory.tar.gz. This command only ever writes " +
			"to disk -- it makes no network calls. Drop the resulting file on the site to " +
			"preview the generated project and its price.",
		RunE: func(_ *cobra.Command, _ []string) error {
			invPath := filepath.Join(outDir, "inventory.json")
			inv, err := os.ReadFile(invPath)
			if err != nil {
				return fmt.Errorf("reading %s (run `inherit scan` first): %w", invPath, err)
			}

			sum := sha256.Sum256(inv)
			manifest, _ := json.Marshal(map[string]string{
				"file":       "inventory.json",
				"sha256":     hex.EncodeToString(sum[:]),
				"created_at": time.Now().UTC().Format(time.RFC3339),
			})

			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			for _, e := range []struct {
				name string
				data []byte
			}{
				{"inventory.json", inv},
				{"manifest.json", append(manifest, '\n')},
			} {
				if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data))}); err != nil {
					return err
				}
				if _, err := tw.Write(e.data); err != nil {
					return err
				}
			}
			if err := tw.Close(); err != nil {
				return err
			}
			if err := gz.Close(); err != nil {
				return err
			}

			tgzPath := filepath.Join(outDir, "inventory.tar.gz")
			if err := os.WriteFile(tgzPath, buf.Bytes(), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "packaged %s (%d bytes, sha256 %s)\n",
				tgzPath, buf.Len(), hex.EncodeToString(sum[:])[:12])
			fmt.Fprintln(os.Stderr, "drop it on the site to preview your project and its price.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&outDir, "out", "o", ".", "the directory `inherit scan` wrote to (default: current directory)")
	return cmd
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
