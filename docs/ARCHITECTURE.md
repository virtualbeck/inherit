# Architecture

```
cmd/inherit         main: calls internal/cli
internal/cli        scan / generate / plan / import commands, the import drivers
internal/awsx       AWS config loading, region listing, the read-only signing guard
internal/discover   resourcegroupstaggingapi sweep, include/exclude filters
internal/hydrate    per-type Describe/Get hydrators, fanouts, gap-fillers, Generic()
internal/prune      drops AWS-materialized noise (default VPCs, region singletons)
internal/redact     moves secret values out of the inventory
internal/emit       inventory -> HCL project (schema-driven, hclwrite)
internal/tf         thin tofu/terraform subprocess driver
internal/nameconv   SDK field name -> schema attribute name (snake-casing, acronyms)
internal/par        bounded concurrency (par.Each) for every worker pool
model               the inventory.json schema (Inventory, Resource)
tfschema            the bundled hashicorp/aws provider schema + its loader
```

Pipeline: `discover` → `hydrate` → `prune` → `redact` → write
`inventory.json` → `emit` → optionally `tf` drives init/validate/plan/import.
`inventory.json` is the seam between the two halves: `inherit generate`
re-runs `emit` from it offline.

## Hard constraints

- **Read-only AWS, enforced.** `internal/awsx/readonly.go` is signing-time SDK
  middleware, not a convention. It matches operation names against a
  read-verb regex (`Describe|List|Get|...`) with small explicit overrides
  (`GetCallerIdentity` allowed; `GetSessionToken` denied despite the verb,
  since it issues credentials). Anything else is rejected before it's signed.
- **inherit never runs a blind `apply`.** Classic import only calls the
  provider's `Read`. `import --fast` (`internal/cli/fastimport.go`) pins every
  resource to `ignore_changes = all`, plans each batch to a file, requires
  every resulting change to be exactly a no-op import, and only then applies
  that saved plan. Batches start at up to 200 resources; one that fails is
  halved and retried (`fastBatches`), and only a batch of 8 or fewer that
  still fails falls back to classic import.
- **Interrupts clean up.** Ctrl-C/SIGTERM cancel the root context
  (`internal/cli/root.go`) instead of killing the process, so the override
  files are always removed. `internal/tf` runs tofu in its own process group
  and forwards one interrupt with a 30s grace before killing it (a second
  SIGINT makes tofu exit immediately, which is what this avoids).
- **No secrets in `.tf` files.** `internal/redact` replaces covered values
  with a sentinel and writes the real ones to `inventory.secrets.json`;
  `internal/emit/unmanaged.go` turns every attribute holding the sentinel into
  a `lifecycle.ignore_changes` entry and documents it in
  `UNMANAGED_FIELDS.md`.

## Discover and hydrate

- Hydrator registration: `register("aws_x", fn)` for top-level types,
  `registerFanout("aws_parent", fn)` for children discovered off a parent
  (SNS subscriptions off a topic). `registry` / `fanoutRegistry` / `arnToTF`
  in `internal/hydrate/registry.go` are the source of truth.
  `docs/COVERAGE.md` is generated from them (`make coverage`).
- Gap-fillers cover what the tagging API never returns.
  `registerGlobalGapFiller` is for region-agnostic APIs (IAM: running it per
  region would duplicate every result), `registerGapFiller` for per-region
  singletons (AWS Config recorder / delivery channel). Gap-filled resources
  skip the main hydrate loop, so they must set their own tags.
- Fanout children don't get tags automatically either (`runFanout` has no
  equivalent of the main loop's `cfg["tags"] = r.Tags`); each fanout sets
  them itself where the schema has a `tags` attribute.
- `Generic()` (`internal/hydrate/generic.go`) shapes an SDK response into
  schema attributes. Two silent failure modes to check first when a type's
  `tofu validate` fails oddly: (1) a `map(string)` attribute is passed through
  untouched, assuming the SDK returns `map[string]string` (it doesn't always:
  DLM `target_tags` is `[]Tag{Key,Value}`); (2) `filterNested` drops a whole
  nested block if any one Required sub-attribute doesn't survive. Prefer a
  hand-built hydrator once a type hits either. Acronym mismatches
  (`VCpuCount`, `MySQLSettings`) are fixed in `nameconv.tokenFix`,
  project-wide.
- `retypeSentinel` lets a hydrator redirect its resource to another Terraform
  type after hydration, for cases the ARN can't tell apart (a VPC's default
  NACL must import as `aws_default_network_acl`).
- `discover.ephemeral` drops point-in-time artifacts (snapshots, AMIs,
  backups) and anything emitted via a fanout/gap-filler, so the ARN sweep
  doesn't duplicate it.
- Gap-filling convention: when a real account's `plan` shows an in-place
  update after import, hydrate the real, recoverable AWS attribute the
  hydrator was dropping. Provider-only directive attributes with no AWS-side
  data (Lambda `publish`) can't be fixed that way; they show a one-time diff.

## Emit

- Schema-driven: `tfschema` (the bundled `tofu providers schema -json`,
  descriptions stripped) gives every attribute's kind and type; `hclwrite`
  renders, so output is valid by construction. Re-bundle with `make schema`.
- Layout: one child module per category, assigned by regex over the Terraform
  type (`categoryFor` in `internal/emit/module.go`, first match wins). The
  root `main.tf` wires modules together; modules never look anything up.
- References: a literal ID/ARN that matches another discovered resource
  becomes a traversal (same module) or an output → variable → root argument
  wire (cross module). Bare IDs that are ambiguous across regions are never
  reference targets. `noRefKeys` / `typeNoRefKeys` / `freeformIDTypes`
  exclude fields whose values only coincidentally match an ID (`name`,
  `tags`, `dimensions`, ...); each one was a real dependency cycle.
- External IDs become hoisted variables with the discovered value as default;
  account ID and region inside ARNs become `data` lookups.
- `default_tags`: a tag is lifted only if it's identical on literally every
  taggable resource, since `default_tags` has no per-resource opt-out.
- Multi-region: a resource outside the default region gets
  `provider = aws.<alias>`, not just `region`, because the per-resource
  `region` attribute isn't consulted during import.
- `for_each` (`internal/emit/foreach.go`): runs of 3+ structurally identical
  same-type resources fold into one block over a `local` map keyed by
  something readable (AZ, CIDR, ...); import blocks use the instance-key
  form. `--for-each=false` disables it.
- Naming ladder (`namer.claim`, `heuristicName`): sole resource of its type in
  the module → `main`; else a usable `Name` tag; else an attribute-derived
  name (`sg_https`, `ingress_5432`, `lambda`, `public`); else a name taken
  from the ID, or `<prefix>_<short hash>` for types whose IDs are opaque.
  Never `sg_01`.

## Testing

- `go test ./...` is offline and fast.
- `make integration` (`INHERIT_INTEGRATION=1`) also runs real `tofu init` +
  `validate` on generated projects and exercises the fast-import safety gate
  with the `hashicorp/local` provider. No AWS credentials. These catch HCL
  that's syntactically valid but semantically wrong.
- `testdata/fixtures/typical-account.json` is a representative synthetic
  inventory (account `999999999999`) driven end to end by
  `internal/cli/generate_test.go`.
