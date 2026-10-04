#!/usr/bin/env bash
# Create a throwaway TLS keystore for running `portal` on a host with no certificate of its
# own. For internal use and local testing only: a self-signed certificate proves nothing about
# who owns the key, so a browser will warn and an operator should replace it with one issued
# by the internal CA before real employees point at it. The program does not care which --
# it loads whatever PKCS12 it is given -- so nothing here has to be redone later.
#
# The password is generated, never typed, and never shown:
#
#   * it comes from the kernel CSPRNG (/dev/urandom), not from the clock or the PID;
#   * it is written to a 0600 file, which is the only place it is stored;
#   * it reaches keytool through the environment (-storepass:env), never as an argument,
#     because argv is world-readable in /proc while a process's own environment is not;
#   * it is never echoed. Nothing that reads this script's output needs the value -- the
#     portal reads the file. Printing it would only move the secret into the terminal
#     scrollback and the operator's shell history.
#
# Refuses to touch an existing keystore, so it can never destroy a live certificate.
set -euo pipefail

DIR="${1:-/etc/portal/tls}"
CN="${2:-portal.internal}"
DAYS="${3:-825}"

if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ]; then
  KEYTOOL="$JAVA_HOME/bin/keytool"
elif command -v keytool >/dev/null 2>&1; then
  KEYTOOL="keytool"
else
  echo "keytool not found. Set JAVA_HOME or run tools/get-jdk.sh." >&2
  exit 1
fi

KS="$DIR/portal.p12"
PWFILE="$DIR/keystore.password"

if [ -e "$KS" ] || [ -e "$PWFILE" ]; then
  echo "REFUSED: $KS or $PWFILE already exists -- nothing was changed." >&2
  echo "Move it away first if you really mean to replace it." >&2
  exit 1
fi

# 0700 on the directory and 0600 on both files from the first byte: umask before create,
# because a keystore that exists world-readable for one instant can be copied in that instant.
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"

# 48 hex characters from the kernel CSPRNG. Hex keeps the value inside the printable-ASCII
# range the portal's secret-file reader requires and excludes characters that a shell,
# a unit file or a properties parser would each want to quote differently.
PW="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
if [ "${#PW}" -lt 32 ]; then
  echo "REFUSED: could not read randomness from /dev/urandom." >&2
  exit 1
fi

( umask 077; printf '%s\n' "$PW" > "$PWFILE" )
chmod 600 "$PWFILE"

export PORTAL_KS_PW="$PW"
# -storepass:env reads the value from the named variable, so it never appears in argv.
"$KEYTOOL" -genkeypair \
  -keystore "$KS" \
  -storetype PKCS12 \
  -storepass:env PORTAL_KS_PW \
  -keypass:env PORTAL_KS_PW \
  -alias portal \
  -keyalg EC -groupname secp384r1 \
  -sigalg SHA384withECDSA \
  -validity "$DAYS" \
  -dname "CN=$CN" \
  -ext "san=dns:$CN,dns:localhost,ip:127.0.0.1,ip:::1" \
  >/dev/null
unset PORTAL_KS_PW

chmod 600 "$KS"

# Prove it loads with the password that was just written, rather than trusting that the two
# commands agreed. A keystore that only keytool can open is worse than no keystore, because
# the failure surfaces at portal startup instead.
"$KEYTOOL" -list -keystore "$KS" -storetype PKCS12 \
  -storepass:file "$PWFILE" -alias portal >/dev/null

echo "created $KS"
echo "created $PWFILE (the password lives only here -- it was not printed)"
ls -l "$KS" "$PWFILE"
cat <<EOF

Then start the portal with absolute paths in the environment, not on the command line:

  export PORTAL_DATA_DIR=/var/lib/portal
  export PORTAL_KEYSTORE=$KS
  export PORTAL_KEYSTORE_PASSWORD_FILE=$PWFILE
  ./portal.sh portal

Clients must trust this certificate (or accept the warning, for local testing only):

  keytool -exportcert -keystore $KS -storetype PKCS12 \\
          -storepass:file $PWFILE -alias portal -rfc -file $DIR/portal.pem
EOF
