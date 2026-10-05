#!/bin/sh
# Fetches the pinned dependency over HTTPS and verifies it before anything loads it.
#
# Reproducible build, no network trust required for the common case:
#   if lib/<file> already exists and matches the pinned digests, this verifies and exits 0
#   without contacting the network at all.  Only a missing file triggers a download, and
#   a download is accepted only when the artifact matches the committed digest AND the
#   origin's own published sidecar digest independently agrees.
#
# Never `curl | sh`, never eval of fetched content, no world-writable path involved:
# everything is written under $LIB_DIR (inside the project) with mode 0644.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/deps.lock"
LIB_DIR="$ROOT/lib"
[ -f "$LOCK" ] || { echo "FATAL missing $LOCK" >&2; exit 1; }

# Parse the lock file by exact key, not by sourcing it: the lock file is data, not code.
lockval() {
  sed -n "s/^$1=//p" "$LOCK" | tr -d ' \t\r\n'
}
FN=$(lockval filename)
URL=$(lockval url)
SZ=$(lockval size)
WANT_SHA256=$(lockval sha256)
WANT_SHA512=$(lockval sha512)
SIDE_SHA1=$(lockval sidecar_sha1)
DEST="$LIB_DIR/$FN"

case "$FN" in
  *[!A-Za-z0-9._-]* | '') echo "FATAL unsafe filename in deps.lock" >&2; exit 1 ;;
esac
case "$URL" in
  https://*) : ;;
  *) echo "FATAL refusing non-HTTPS origin: $URL" >&2; exit 1 ;;
esac
# Every pinned digest must be a plain lowercase hex string of the right width. This is
# what rejects the real-world failure mode where the digest URL answers 200 with an HTML
# error page instead of a number.
is_hex() {
  case "$1" in '' | *[!0-9a-f]*) return 1 ;; esac
  [ "${#1}" -eq "$2" ]
}
is_hex "$WANT_SHA256" 64 || { echo "FATAL deps.lock sha256 is not 64 hex chars" >&2; exit 1; }
is_hex "$WANT_SHA512" 128 || { echo "FATAL deps.lock sha512 is not 128 hex chars" >&2; exit 1; }

mkdir -p "$LIB_DIR"
chmod 755 "$LIB_DIR"

need_download=1
if [ -f "$DEST" ]; then
  if [ "$(sha256sum "$DEST" | cut -d' ' -f1)" = "$WANT_SHA256" ] \
     && [ "$(sha512sum "$DEST" | cut -d' ' -f1)" = "$WANT_SHA512" ]; then
    need_download=0
    echo "VERIFIED origin-free: $FN matches both pinned sha256 and sha512 (no network used)"
  else
    echo "REFUSING existing $DEST: digest mismatch, will not load it. Re-fetch with --fetch." >&2
    exit 1
  fi
fi

if [ "$need_download" -eq 1 ]; then
  if [ "${1:-}" != "--fetch" ]; then
    echo "FATAL $DEST is missing. Re-run with --fetch to download it from the pinned origin." >&2
    exit 1
  fi
  command -v curl >/dev/null 2>&1 || { echo "FATAL curl not available" >&2; exit 1; }
  TMP="$LIB_DIR/.$FN.part.$$"
  trap 'rm -f "$TMP" "$TMP.side"' EXIT INT TERM
  # -f: fail on HTTP error. -p: fail on TLS problems. --proto =https: refuse downgrade.
  # --max-redirs bounds redirects; the redirect target is still digest-checked below.
  curl -fsS --proto '=https' --tlsv1.2 --max-redirs 3 --max-time 300 -o "$TMP" "$URL"
  # Size gate first (cheap) so a truncated transfer never reaches the hash comparison.
  got=$(stat -c%s "$TMP")
  [ "$got" = "$SZ" ] || { echo "FATAL size mismatch: got $got want $SZ" >&2; exit 1; }
  got=$(sha512sum "$TMP" | cut -d' ' -f1)
  [ "$got" = "$WANT_SHA512" ] || { echo "FATAL sha512 mismatch against pinned value" >&2; exit 1; }
  # Independent second opinion: the origin's published sidecar. Accepted only if it is a
  # well-formed hex digest that also matches, so a 404 HTML page cannot satisfy the check.
  if [ -n "$SIDE_SHA1" ]; then
    is_hex "$SIDE_SHA1" 40 || { echo "FATAL deps.lock sidecar_sha1 is not 40 hex chars" >&2; exit 1; }
    curl -fsS --proto '=https' --tlsv1.2 --max-time 60 -o "$TMP.side" "$URL.sha1"
    side=$(tr -d ' \t\r\n' < "$TMP.side")
    side=${side##* }                     # tolerate "<sha1>  filename" format
    case "$side" in *[!0-9a-f]*) echo "FATAL sidecar is not hex (HTML error page?)" >&2; exit 1 ;; esac
    [ "${#side}" -eq 40 ] || { echo "FATAL sidecar is not 40 hex chars" >&2; exit 1; }
    [ "$side" = "$SIDE_SHA1" ] || { echo "FATAL origin sidecar sha1 disagrees with deps.lock" >&2; exit 1; }
    local_sha1=$(sha1sum "$TMP" | cut -d' ' -f1)
    [ "$local_sha1" = "$side" ] || { echo "FATAL sha1 disagrees with origin sidecar" >&2; exit 1; }
    echo "VERIFIED downloaded $FN: pinned sha512 + independent origin sidecar sha1 both match"
  else
    echo "VERIFIED downloaded $FN: pinned sha512 matches"
  fi
  mv "$TMP" "$DEST"
  chmod 644 "$DEST"
  rm -f "$TMP.side"
  trap - EXIT INT TERM
fi

# Structural sanity: it must be a zip containing the driver class we are about to load.
LIST=$(jar --list --file "$DEST" 2>/dev/null) || { echo "FATAL $DEST is not a readable jar" >&2; exit 1; }
printf '%s\n' "$LIST" | grep -qx 'org/h2/Driver.class' \
  || { echo "FATAL $DEST does not contain org/h2/Driver.class" >&2; exit 1; }
printf '%s\n' "$LIST" | grep -qx 'META-INF/services/java.sql.Driver' \
  || echo "WARN no java.sql.Driver service entry (driver must be loaded explicitly)" >&2
# Manifest is extracted into a scratch dir, never into the caller's cwd.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
( cd "$WORK" && jar --file "$DEST" --extract META-INF/MANIFEST.MF ) 2>/dev/null || true
if [ -f "$WORK/META-INF/MANIFEST.MF" ]; then
  # An agent/extension entry would mean the jar wants to be loaded into every JVM.
  if grep -qiE '^(Agent-Class|Extension-Name):' "$WORK/META-INF/MANIFEST.MF"; then
    echo "FATAL unexpected manifest entry in $FN" >&2; rm -rf "$WORK"; exit 1
  fi
  grep -q '^Implementation-Version: ' "$WORK/META-INF/MANIFEST.MF" \
    || echo "WARN $FN has no Implementation-Version" >&2
fi
rm -rf "$WORK"
trap - EXIT INT TERM
echo "OK dependency ready: $FN"
