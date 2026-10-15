// Command inherit turns a live, non-IaC AWS account into a working
// OpenTofu/Terraform project: read-only discovery, schema-driven HCL
// generation, and (optionally) state import, all on your own machine.
package main

import "github.com/virtualbeck/inherit/internal/cli"

func main() {
	cli.Execute()
}
