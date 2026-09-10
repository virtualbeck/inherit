// Command genschema regenerates internal/tfschema/schema/aws.min.json.gz from a
// live `tofu`/`terraform providers schema -json` dump, with descriptions
// stripped. Run from the repo root: go run ./internal/tfschema/cmd/genschema
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const providerConstraint = "~> 6.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}
}

func run() error {
	bin := "tofu"
	if _, err := exec.LookPath(bin); err != nil {
		bin = "terraform"
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("need tofu or terraform on PATH")
		}
	}

	dir, err := os.MkdirTemp("", "inherit-genschema-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	main := fmt.Sprintf(`terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = %q
    }
  }
}
`, providerConstraint)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o644); err != nil {
		return err
	}

	if out, err := runIn(dir, bin, "init", "-input=false", "-no-color"); err != nil {
		return fmt.Errorf("%s init: %v\n%s", bin, err, out)
	}
	raw, err := runIn(dir, bin, "providers", "schema", "-json")
	if err != nil {
		return fmt.Errorf("%s providers schema: %v", bin, err)
	}

	var doc struct {
		ProviderSchemas map[string]struct {
			ResourceSchemas map[string]struct {
				Block json.RawMessage `json:"block"`
			} `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return err
	}
	var key string
	for k := range doc.ProviderSchemas {
		if strings.HasSuffix(k, "/hashicorp/aws") {
			key = k
		}
	}
	if key == "" {
		return fmt.Errorf("hashicorp/aws not in schema output")
	}

	mini := map[string]any{}
	for name, rs := range doc.ProviderSchemas[key].ResourceSchemas {
		var b map[string]any
		_ = json.Unmarshal(rs.Block, &b)
		mini[name] = stripBlock(b)
	}
	blob, err := json.Marshal(map[string]any{"resource_schemas": mini})
	if err != nil {
		return err
	}

	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write(blob)
	_ = zw.Close()

	dst := filepath.Join("internal", "tfschema", "schema", "aws.min.json.gz")
	if err := os.WriteFile(dst, gz.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d resource types, %d bytes gz)\n", dst, len(mini), gz.Len())
	return nil
}

func stripBlock(b map[string]any) map[string]any {
	if b == nil {
		return nil
	}
	out := map[string]any{}
	if attrs, ok := b["attributes"].(map[string]any); ok {
		na := map[string]any{}
		for name, av := range attrs {
			a, _ := av.(map[string]any)
			e := map[string]any{}
			if t := a["type"]; t != nil {
				e["type"] = t
			}
			for _, f := range []string{"required", "optional", "computed"} {
				if v, _ := a[f].(bool); v {
					e[f] = true
				}
			}
			if nt, ok := a["nested_type"].(map[string]any); ok {
				e["nested_type"] = map[string]any{
					"nesting_mode": nt["nesting_mode"],
					"block":        stripBlock(nt),
				}
			}
			na[name] = e
		}
		if len(na) > 0 {
			out["attributes"] = na
		}
	}
	if bts, ok := b["block_types"].(map[string]any); ok {
		nb := map[string]any{}
		for name, btv := range bts {
			bt, _ := btv.(map[string]any)
			inner, _ := bt["block"].(map[string]any)
			e := map[string]any{
				"nesting_mode": bt["nesting_mode"],
				"block":        stripBlock(inner),
			}
			if v, ok := bt["min_items"]; ok {
				e["min_items"] = v
			}
			if v, ok := bt["max_items"]; ok {
				e["max_items"] = v
			}
			nb[name] = e
		}
		if len(nb) > 0 {
			out["block_types"] = nb
		}
	}
	return out
}

func runIn(dir, bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
