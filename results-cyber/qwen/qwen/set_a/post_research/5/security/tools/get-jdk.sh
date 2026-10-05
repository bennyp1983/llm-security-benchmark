#!/usr/bin/env bash
# Fetch and verify the JDK this project is built and tested with. This is the ONLY network
# fetch in the entire build: the program itself has no third-party runtime dependencies, so
# there is no dependency tree to resolve, pin or audit.
#
# The digest below is the SHA-256 published by Adoptium for this exact asset (it is also
# served next to the tarball as <link>.sha256). The download is refused on any mismatch, so
# a truncated or substituted archive cannot silently become this build's compiler.
set -euo pipefail

VERSION="jdk-21.0.12.1+1"
FILE="OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
URL="https://github.com/adoptium/temurin21-binaries/releases/download/${VERSION/%+/%2B}/${FILE}"
SHA256="ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"
DEST="${1:-/opt/tools}"

if [ -x "$DEST/jdk-$VERSION/bin/java" ]; then
  echo "already present: $DEST/jdk-$VERSION"
  exit 0
fi

mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching $URL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/$FILE" "$URL"

echo "$SHA256  $TMP/$FILE" > "$TMP/expected.sha256"
if ! sha256sum --check --strict "$TMP/expected.sha256"; then
  echo "REFUSED: checksum mismatch for $FILE" >&2
  exit 1
fi

tar -xzf "$TMP/$FILE" -C "$DEST"
echo "installed $DEST/jdk-$VERSION"
"$DEST/jdk-$VERSION/bin/java" -version
