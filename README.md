# inherit

Inherited an AWS account that isn't infrastructure-as-code? This is the free,
open-source half of **inherit**: it runs **on your machine**, discovers what's
in the account using **read-only AWS APIs only**, and writes a flat
`inventory.json` describing it.

That file is the input to the inherit backend, which turns it into a working
OpenTofu/Terraform project. **The backend is the paid product; this tool is
not.** Everything here is auditable. The point of splitting it out is that the
half that touches your account is open.

## What it does and doesn't do

- `inherit scan` makes **no network calls except to read-only AWS APIs**
  (`Describe*` / `List* `/ `Get*` + `sts:GetCallerIdentity`). A signing-time
  guard rejects anything else before it leaves the process.
- `inherit submit` makes **no network calls at all**. It packages the
  redacted `inventory.json` into `inventory.tar.gz` on disk; you drop that
  file on the site yourself to preview the generated project and its price.
- It never writes, changes, or deletes anything in your account.

## Redaction

A handful of fields legitimately end up in Terraform config but routinely hold
secrets: Lambda environment variables, EC2 `user_data`, and plain
(non-`SecureString`) SSM parameter values. `scan` replaces these with a
marker in `inventory.json` and writes the real values to a local
`inventory.secrets.json` (auto-gitignored, never uploaded). The delivered
Terraform uses `lifecycle { ignore_changes }` for them and ships a guide for
wiring them back up.

Secrets Manager values, RDS/Redshift master passwords, and SSM `SecureString`
are never read in the first place.

An AWS access key ID (`AKIA...`/`ASIA...`) is redacted wherever it turns up
in a resource's config, not just the fields above -- confirmed against a
real account: IAM users tagged with their own access key ID as the tag
*key*, a common way to label "which key is this". The tag's human label
(the value) stays legible; only the key ID itself is stripped.

ECS container `environment[]` values are **not** redacted -- there's no
reliable way to tell a real secret apart from ordinary plaintext config
(log level, hostname, feature flags) there, and AWS itself never treats the
field as sensitive (`secrets[]`, the actually-encrypted path, is untouched
either way). If a real secret ended up in `environment[]` instead of
`secrets[]`, that happened in the live account before `inherit` ever saw it.

## Installation

### macOS / Linux

```sh
curl -fsSL https://raw.githubusercontent.com/virtualbeck/inherit/main/install.sh | sh
```

Downloads the right binary for your OS/arch, verifies it against the
release's `SHA256SUMS`, and installs it to `~/.local/bin/inherit` -- no
`sudo`, nothing written outside your home directory. Re-run any time to
update. If `~/.local/bin` isn't already on your `PATH`, the script tells you
the line to add.

Prefer to do it by hand, or want it somewhere else (`INHERIT_INSTALL_DIR`
overrides the install directory)? Grab a binary directly from
[Releases](https://github.com/virtualbeck/inherit/releases):

```sh
curl -LO https://github.com/virtualbeck/inherit/releases/latest/download/inherit_<version>_<os>_<arch>
chmod +x inherit_<version>_<os>_<arch>
mv inherit_<version>_<os>_<arch> ~/.local/bin/inherit   # or /usr/local/bin, if you'd rather it be system-wide
```

`<os>` is `darwin` or `linux`; `<arch>` is `amd64` or `arm64` (`arm64` on
Apple Silicon). On macOS the binary is unsigned, so the first run will need
`xattr -d com.apple.quarantine <path>` or an approval click through
**System Settings > Privacy & Security**.

Verify any download against the `SHA256SUMS` file published alongside each
release -- `install.sh` above does this for you automatically.

### Windows

Download `inherit_<version>_windows_<arch>.exe` from the
[Releases](https://github.com/virtualbeck/inherit/releases) page (`amd64` or
`arm64`), then run it from PowerShell or `cmd.exe`. It isn't code-signed, so
SmartScreen will flag it on first run; click **More info > Run anyway**, or
build from source if you'd rather not.

Verify any download against the `SHA256SUMS` file published alongside each
release.

## Usage

```sh
inherit scan --profile my-readonly-profile --regions us-east-1 --out ./inherit-<account>
cd ./inherit-<account> && inherit submit
```

`submit` defaults `--out` to the current directory, so it just needs to run
from wherever `scan` wrote its output -- pass `--out` explicitly instead if
you'd rather not `cd`. Either way it packages `inventory.tar.gz` in that
directory; drop it on the site to preview your generated project and its
price.

`scan` is a point-in-time snapshot. If something in the account gets
created, changed, or torn down after you scan but before you run
`tofu import`/`apply` on the delivered project, that drift is real and
expected -- `tofu plan` will tell you (e.g. "Cannot import non-existent
remote object" for something deleted in between). Run `scan` -> `submit`
-> apply reasonably close together, especially against an account with
anything actively churning.

## Build

```sh
go build ./cmd/inherit
```

`make dist` cross-compiles release binaries for macOS, Linux, and Windows
(amd64 + arm64 each) into `dist/`.

## License

Apache-2.0 (`LICENSE`). The **inherit** name and branding are reserved;
see `TRADEMARK.md`.
