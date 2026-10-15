# inherit

Inherited an AWS account that isn't infrastructure-as-code? Start here.

`inherit` is one small binary that runs **on your machine**, discovers what's
in an AWS account using **read-only AWS APIs only**, and writes a working
OpenTofu/Terraform project describing it, ready to `init` / `validate` /
`plan` / `import`.

```sh
inherit scan --profile my-readonly-profile     # discover + generate ./inherit-<account>/
inherit plan   inherit-<account>                # tofu init + validate + plan
inherit import inherit-<account>                # bring every resource into local state
```

![inherit scanning, planning and importing a simulated AWS account](docs/demo.gif)

<sub>A simulated account (999999999999), paced to real timings. Source: [`demo/demo.tape`](demo/demo.tape).</sub>

## What it does and doesn't do

- `inherit scan` makes **no network calls except read-only AWS APIs**
  (`Describe*` / `List*` / `Get*` + `sts:GetCallerIdentity`). A signing-time
  guard rejects anything else before it leaves the process.
- It never writes, changes, or deletes anything in your account.
  `inherit import` uses classic `import`, which only ever calls the
  provider's `Read`. `inherit import --fast` batches imports through `apply`,
  but only on a plan it has first verified contains nothing but no-op
  imports (see [How it works](#how-it-works)).
- Nothing is sent anywhere else. Your inventory, your secrets and your
  generated project stay on your disk.

## How it works

1. **Discover.** `resourcegroupstaggingapi:GetResources` swept across every
   enabled region in parallel, plus gap-fillers for what that API never
   returns.
2. **Hydrate.** A per-resource-type fetcher calls the specific
   `Describe`/`Get` operations for full configuration.
3. **Prune.** Drop unused, default resources from the report, when unused.
4. **Redact.** As described under [Secrets](#secrets).
5. **Generate.** The AWS provider's own JSON schema tells the
   generator every attribute's kind and type, and output is written with
   `hclwrite`, so the HCL is valid by construction.
6. **Import.**
   a. `inherit import` runs one classic `import` per resource, safe but slow.
   b. `inherit import --fast` batches instead, never applies a batch blind.

More detail on the internals: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installation

### macOS / Linux

```sh
curl -fsSL https://raw.githubusercontent.com/virtualbeck/inherit/main/install.sh | sh
```

Downloads the right binary for your OS/arch, verifies it against the
release's `SHA256SUMS`, and installs it to `~/.local/bin/inherit`: no
`sudo`, nothing written outside your home directory. Re-run any time to
update. `INHERIT_INSTALL_DIR` overrides the install directory.

Or grab an archive from [Releases](https://github.com/virtualbeck/inherit/releases)
(`inherit_<version>_<os>_<arch>.tar.gz`, `<os>` = `darwin` | `linux`,
`<arch>` = `amd64` | `arm64`), verify it against `SHA256SUMS`, and put the
`inherit` binary inside on your `PATH`. On macOS the binary is unsigned, so
the first run needs `xattr -d com.apple.quarantine <path>` or an approval in
**System Settings > Privacy & Security**.

### Windows

Download `inherit_<version>_windows_<arch>.zip` from
[Releases](https://github.com/virtualbeck/inherit/releases) and extract
`inherit.exe`. It isn't code-signed, so SmartScreen flags it on first run (**More info > Run
anyway**).

### From source

```sh
go install github.com/virtualbeck/inherit/cmd/inherit@latest   # Go 1.27+
```

`plan` and `import` need [OpenTofu](https://opentofu.org) (preferred) or
Terraform on your `PATH`. `scan` and `generate` don't.

## Usage

```
inherit scan       discover the account (read-only) and generate the project
inherit generate   regenerate the project from an existing inventory.json (offline)
inherit plan       tofu init + validate + plan against a generated project
inherit import     plan, plus state-only import of every resource (--fast: batched)
```

Authenticate however you normally do (env vars, SSO, a profile): `inherit`
reads the standard AWS SDK chain and shows you the account, identity and
regions it resolved before doing anything. A read-only identity is enough:
the AWS-managed `ReadOnlyAccess` policy, or
[docs/iam-policy.json](docs/iam-policy.json) (read-only verbs only).

```sh
inherit scan                                     # every enabled region, confirm prompt
inherit scan --profile prod-readonly -y          # pick a profile, skip the prompt
inherit scan --regions us-east-1,eu-west-1       # narrow the regions
inherit scan --services-exclude cloudformation,guardduty    # skip whole services
inherit scan --services-exclude cloudformation:stackset     # ...or one resource type
inherit scan --services-include ec2,s3           # scan ONLY these services
inherit scan --include-ephemeral                 # keep snapshots / AMIs / backups
inherit scan --include-defaults                  # keep default VPCs + per-region singletons
inherit scan -e prod                             # label the example state key in backend.tf
inherit scan --for-each=false                    # one block per resource, no for_each folding
inherit scan --debug                             # per-region counts + every hydration error

inherit plan inherit-123456789012
inherit import inherit-123456789012              # one `import` per resource, Read-only
inherit import --fast inherit-123456789012       # far faster on hundreds of resources
inherit generate inherit-123456789012            # re-render after upgrading inherit
inherit plan --tf-bin terraform inherit-123456789012   # use terraform instead of tofu
```

`plan` and `import` prefer `tofu` and fall back to `terraform`. `import`
exits non-zero if any resource failed to import (it still runs the final
`plan`, which shows exactly what's missing); re-running it picks up where it
left off, skipping everything already in state. Ctrl-C is safe: tofu is
interrupted gracefully and `--fast` removes its temporary override files
before exiting.

Each run is one account into one directory: `./inherit-<account>` by default,
with a unix-timestamp suffix if that already exists (re-generating into a
prior run's directory can leave stale state behind). `--out` picks your own
path, used as given.

`scan` is a point-in-time snapshot. If something changes in the account
between `scan` and `import`, `tofu plan` will tell you (for example, "Cannot
import non-existent remote object" for something deleted in between).

### What you get

```
inherit-123456789012/
  inventory.json          what was discovered (secrets redacted)
  inventory.secrets.json  the redacted values (gitignored; never commit it)
  .gitignore              secrets, state and plan files, .terraform/
  versions.tf             required OpenTofu/provider versions
  providers.tf            the aws provider, plus one alias per extra region
  main.tf                 the root module: every category module, wired together
  imports.tf              one import {} block per resource
  backend.tf              local state by default, with a commented S3 skeleton
  UNMANAGED_FIELDS.md     attributes left to ignore_changes (only if anything was redacted)
  README.md
  modules/<category>/     compute, network, database, storage, security, ...
```

### Secrets

The generated project never contains those values. Each affected attribute is
listed under the resource's `lifecycle { ignore_changes = [...] }`, so the
project plans clean on day one, and `UNMANAGED_FIELDS.md` lists every one with
the ARN to look up in `inventory.secrets.json` when you're ready to wire it to
a secret store. 
- Secrets Manager values, RDS/Redshift master passwords and SSM `SecureString`
  values are never read in the first place. 
- ECS container `environment[]` values are **not** redacted: nothing reliably
  tells a secret apart from plain config

Note that `terraform.tfstate` holds real attribute values once you import.
It's gitignored; treat it as sensitive.

## Known limitations

A few provider-only directive attributes have no AWS-side data at all (Lambda
`publish`, an SNS subscription's `confirmation_timeout_in_minutes`, a
CloudFormation StackSet's `call_as`, ...). They show a one-time diff on the
first `plan` after import because the provider's `Read` never populates them.
That's harmless: one no-op `apply` settles it.

Lambda code isn't recoverable from the API. Functions without an S3 or image
source point at a placeholder zip in their module, which you swap for the
real build.

## Development

```sh
make             # vet + test + build ./bin/inherit
make test        # go test ./...
make integration # + real tofu init/validate runs (needs tofu/terraform + network)
make lint        # golangci-lint
make dist        # release archives for linux/darwin/windows x amd64/arm64 in dist/
make coverage    # regenerate docs/COVERAGE.md from the hydrator registry
make schema      # re-bundle the latest hashicorp/aws 6.x provider schema
make demo        # re-render the demo GIF/video with VHS (needs docker)
```

The website is `site/index.html`, published by GitHub Pages on every change.

The demo is a [VHS](https://github.com/charmbracelet/vhs) tape that drives
`demo/bin/inherit`, a stand-in that replays recorded output for a simulated
account (`demo/replay/`), so it needs no AWS access. The tape's `Sleep`s set
the pacing to match real runs.

## License

Apache-2.0. See [LICENSE](LICENSE).
