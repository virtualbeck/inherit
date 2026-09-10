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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func submitCmd() *cobra.Command {
	var (
		outDir   string
		endpoint string
		dryRun   bool
	)
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Package inventory.json into inventory.tar.gz and upload it to the backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
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

			if dryRun || endpoint == "" {
				fmt.Fprintln(os.Stderr, "no --endpoint set: upload skipped. Upload inventory.tar.gz through the site.")
				return nil
			}

			fmt.Fprintf(os.Stderr, "uploading to %s ...\n", endpoint)
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost,
				strings.TrimRight(endpoint, "/")+"/submit", bytes.NewReader(buf.Bytes()))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/gzip")
			resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if resp.StatusCode/100 != 2 {
				return fmt.Errorf("backend returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			fmt.Fprintf(os.Stderr, "done. %s\n", strings.TrimSpace(string(body)))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&outDir, "out", "o", "", "the directory `inherit scan` wrote to")
	f.StringVar(&endpoint, "endpoint", os.Getenv("INHERIT_ENDPOINT"), "backend base URL (default: $INHERIT_ENDPOINT)")
	f.BoolVar(&dryRun, "dry-run", false, "package inventory.tar.gz but do not upload")
	_ = cmd.MarkFlagRequired("out")
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
