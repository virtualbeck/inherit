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
- `inherit submit` makes exactly one additional call: uploading the redacted
  `inventory.json` to the backend. It has a browser-upload fallback if your
  environment blocks that.
- It never writes, changes, or deletes anything in your account.

## Redaction

A handful of fields legitimately end up in Terraform config but routinely hold
secrets: Lambda environment variables, EC2 `user_data`, ECS container
environment, and plain (non-`SecureString`) SSM parameter values. `scan`
replaces these with a marker in `inventory.json` and writes the real values to
a local `inventory.secrets.json` (auto-gitignored, never uploaded). The
delivered Terraform uses `lifecycle { ignore_changes }` for them and ships a
guide for wiring them back up.

Secrets Manager values, RDS/Redshift master passwords, and SSM `SecureString`
are never read in the first place.

## Installation

Grab a prebuilt binary from the [Releases](https://github.com/virtualbeck/inherit/releases)
page, or build from source (see [Build](#build)).

### macOS

```sh
curl -LO https://github.com/virtualbeck/inherit/releases/latest/download/inherit_<version>_darwin_<arch>
chmod +x inherit_<version>_darwin_<arch>
sudo mv inherit_<version>_darwin_<arch> /usr/local/bin/inherit
```

`<arch>` is `arm64` on Apple Silicon, `amd64` on Intel Macs. The binary is
unsigned, so the first run will need `xattr -d com.apple.quarantine
/usr/local/bin/inherit` or an approval click through **System
Settings > Privacy & Security**.

### Linux

```sh
curl -LO https://github.com/virtualbeck/inherit/releases/latest/download/inherit_<version>_linux_<arch>
chmod +x inherit_<version>_linux_<arch>
sudo mv inherit_<version>_linux_<arch> /usr/local/bin/inherit
```

`<arch>` is `amd64` or `arm64`.

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
inherit scan --profile my-readonly-profile --regions us-east-1
inherit submit --out ./inherit-<account>
```

## Build

```sh
go build ./cmd/inherit
```

`make dist` cross-compiles release binaries for macOS, Linux, and Windows
(amd64 + arm64 each) into `dist/`.

## License

Apache-2.0 (`LICENSE`). The **inherit** name and branding are reserved;
see `TRADEMARK.md`.
