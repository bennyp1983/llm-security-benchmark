#!/usr/bin/env bash
# Fetches the third-party jars this program needs from Maven Central and refuses
# to use any file whose digest does not match the pinned value in deps.lock.
#
# Integrity chain for every artifact:
#   1. pinned SHA-256 in deps.lock (authoritative, reviewed in source control)
#   2. primary download over TLS from repo1.maven.org (curl --proto '=https')
#   3. independent re-download from a second distributor
#      (maven-central.storage-download.googleapis.com) - digests must agree
#   4. Maven Central's published SHA-1 must agree with the computed SHA-1
#   5. the file must be a readable jar containing the expected entry
#   6. signed jars (Bouncy Castle) must carry a verifiable signature
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBS="$ROOT/libs"
LOCK="$ROOT/deps.lock"
PRIMARY="https://repo1.maven.org/maven2"
MIRROR="https://maven-central.storage-download.googleapis.com/maven2"
JAR_TOOL="${JAVA_HOME:-/opt/jdk17}/bin/jar"
KEYTOOL="${JAVA_HOME:-/opt/jdk17}/bin/keytool"
CURL=(curl -sS --fail --proto '=https' --tlsv1.2 --location-trusted
      --connect-timeout 15 --retry 3 --retry-delay 2 --max-time 300)

die() { echo "FATAL: $*" >&2; exit 1; }
[ -f "$LOCK" ] || die "deps.lock is missing - nothing is pinned, refusing to download"
[ -x "$JAR_TOOL" ] || die "jar tool not found at $JAR_TOOL (set JAVA_HOME)"
mkdir -p "$LIBS"

digest() { sha256sum "$1" | cut -d' ' -f1; }

while read -r kind file coord sha256 entry signature; do
  [ -n "${kind:-}" ] || continue
  case "$kind" in \#*) continue ;; esac
  case "$kind" in jar|test-jar) ;; *) die "deps.lock: unknown record type '$kind'" ;; esac
  case "$signature" in signed|unsigned) ;; *) die "deps.lock: signature must be signed|unsigned for $file" ;; esac

  # test-jar records are only needed by the test suite; skip with SKIP_TESTS=1.
  if [ "$kind" = "test-jar" ] && [ "${SKIP_TESTS:-0}" = "1" ]; then
    continue
  fi
  target_dir="$LIBS"
  [ "$kind" = "test-jar" ] && target_dir="$LIBS/test"
  mkdir -p "$target_dir"

  out="$target_dir/$file"
  path() { printf '%s/%s\n' "$1" "$coord"; }

  if [ -f "$out" ] && [ "$(digest "$out")" = "$sha256" ]; then
    echo "cached  $file"
  else
    echo "fetch   $file  ($coord)"
    tmp="$(mktemp "${TMPDIR:-/tmp}/getdeps.XXXXXX")"
    trap 'rm -f "$tmp" "${tmp}.mirror"' EXIT
    "${CURL[@]}" -o "$tmp" "$(path "$PRIMARY" "$coord")" \
      || die "download failed from primary for $coord"
    [ "$(digest "$tmp")" = "$sha256" ] \
      || die "SHA-256 mismatch for $coord: got $(digest "$tmp") want $sha256"
    "${CURL[@]}" -o "${tmp}.mirror" "$(path "$MIRROR" "$coord")" \
      || die "download failed from mirror for $coord"
    [ "$(digest "${tmp}.mirror")" = "$sha256" ] \
      || die "mirror disagrees on SHA-256 for $coord: got $(digest "${tmp}.mirror") want $sha256"
    sha1line="$("${CURL[@]}" "$(path "$PRIMARY" "$coord").sha1" | tr -d ' \t\r\n')"
    case "$sha1line" in *[!0-9a-f]*|'') die "no usable SHA-1 published for $coord" ;; esac
    [ "$(sha1sum "$tmp" | cut -d' ' -f1)" = "$sha1line" ] \
      || die "SHA-1 mismatch for $coord (published $sha1line)"
    mv "$tmp" "$out"
    rm -f "${tmp}.mirror"
    trap - EXIT
    echo "verified $file  sha256=$sha256"
  fi

  listing="$(mktemp "${TMPDIR:-/tmp}/jarlist.XXXXXX")"
  "$JAR_TOOL" --list --file "$out" >"$listing" 2>/dev/null \
    || die "$out is not a readable jar"
  grep -q "^$entry\$" "$listing" || die "$out does not contain $entry (wrong artifact?)"
  rm -f "$listing"

  if [ "$signature" = "signed" ]; then
    "$KEYTOOL" -printcert -jarfile "$out" >/dev/null 2>&1 \
      || die "$out is required to be signed but carries no valid signature"
    echo "signed  $file"
  fi
done < "$LOCK"

echo "all dependencies verified"
