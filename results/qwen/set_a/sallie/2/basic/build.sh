#!/bin/sh
# Compiles the program and its tests, runs the tests, then runs the demo if a
# passphrase can be supplied without typing.
set -e

cd "$(dirname "$0")"

echo "==> compiling"
rm -rf out
mkdir -p out
javac -Xlint:all -Werror -d out src/*.java test/*.java

echo "==> running the tests (about half a minute, most of it key stretching)"
java -cp out PiiCryptoTest

echo "==> demo"
if [ -n "${PII_PASSPHRASE:-}" ]; then
    java -cp out PiiApp "Ada Lovelace" "ada@example.com"
elif [ -t 0 ]; then
    # A terminal is attached, so let the program ask for the passphrase itself.
    java -cp out PiiApp
else
    echo "skipped: no terminal to type a passphrase into."
    echo "run it yourself with either of:"
    echo "  java -cp out PiiApp \"Ada Lovelace\" \"ada@example.com\""
    echo "  PII_PASSPHRASE='a long phrase you will remember' java -cp out PiiApp \"Ada Lovelace\" \"ada@example.com\""
fi
