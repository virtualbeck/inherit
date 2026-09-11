#!/bin/sh
# Installs the latest inherit release for macOS or Linux into a user-space
# bin directory -- no sudo, no system-wide write. Re-run any time to update.
#
#   curl -fsSL https://raw.githubusercontent.com/virtualbeck/inherit/main/install.sh | sh
#
# Windows: grab the .exe from the Releases page instead (see README).
set -eu

REPO="virtualbeck/inherit"
BIN="inherit"
INSTALL_DIR="${INHERIT_INSTALL_DIR:-$HOME/.local/bin}"

os() {
	case "$(uname -s)" in
	Linux) echo linux ;;
	Darwin) echo darwin ;;
	*)
		echo "unsupported OS: $(uname -s). Grab a binary from the Releases page instead:" >&2
		echo "  https://github.com/$REPO/releases" >&2
		exit 1
		;;
	esac
}

arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*)
		echo "unsupported architecture: $(uname -m)" >&2
		exit 1
		;;
	esac
}

OS=$(os)
ARCH=$(arch)

TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
	grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
if [ -z "$TAG" ]; then
	echo "couldn't determine the latest release tag" >&2
	exit 1
fi

ASSET="${BIN}_${TAG}_${OS}_${ARCH}"
BASE_URL="https://github.com/$REPO/releases/download/$TAG"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "downloading $ASSET ($TAG) ..." >&2
curl -fsSL -o "$WORK/$ASSET" "$BASE_URL/$ASSET"
curl -fsSL -o "$WORK/SHA256SUMS" "$BASE_URL/SHA256SUMS"

echo "verifying checksum ..." >&2
( cd "$WORK" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - ) 2>/dev/null ||
	( cd "$WORK" && grep " $ASSET\$" SHA256SUMS | shasum -a 256 -c - )

mkdir -p "$INSTALL_DIR"
chmod +x "$WORK/$ASSET"
mv "$WORK/$ASSET" "$INSTALL_DIR/$BIN"

echo "installed $INSTALL_DIR/$BIN ($TAG)" >&2

case ":$PATH:" in
*":$INSTALL_DIR:"*) ;;
*)
	echo "" >&2
	echo "$INSTALL_DIR isn't on your PATH. Add this to your shell profile:" >&2
	echo "  export PATH=\"$INSTALL_DIR:\$PATH\"" >&2
	;;
esac
