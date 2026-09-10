# vendored provider schema

`aws.min.json.gz` is `tofu providers schema -json` for `hashicorp/aws` with the
free-text descriptions stripped and re-minified. It records, per resource type,
every attribute's kind (attribute vs nested block), cty type, and
required/optional/computed flags, the ground truth the emitter uses so the
generated HCL is valid by construction.

Regenerate with `go run ./internal/tfschema/cmd/genschema` (needs `tofu` or
`terraform` on PATH). Current: AWS provider **v6.62.0**.
