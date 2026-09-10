#!/usr/bin/env bash
# End-to-end demonstration of the administrator portal. Uses a low PBKDF2 cost and a short demo
# directory so it runs fast; production uses the default 310,000 iterations.
#
# Every denied step below is expected to exit non-zero; the script reports the code it observed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CP="$HERE/build"
HOME_DIR="${1:-/tmp/admin-portal-demo}"
ITERS="--iterations 20000"
PW_ALICE='Corr3ct-Horse-Battery'
PW_BOB='An0ther-Strong-Pass'

rm -rf "$HOME_DIR"
run() { # run <expected-exit> <label> <stdin> <args...>
  local want="$1" label="$2" stdin="$3"; shift 3
  echo "----- $label"
  printf '%s\n' "$stdin" | java -cp "$CP" adminportal.AdminPortal "$@" $ITERS --home "$HOME_DIR"
  local got=$?
  if [ "$got" = "$want" ]; then echo "[exit $got as expected]"; else echo "[UNEXPECTED exit $got, wanted $want]"; fi
  echo
}

echo "=== 1. first-run bootstrap: the only unauthenticated provisioning step ==="
run 0 "create the first administrator (alice)" "$PW_ALICE" add-user alice

echo "=== 2. provisioning is privileged once an account exists ==="
run 1 "attempt to add 'mallory' with a wrong authorising password" "wrong" add-user mallory --user alice

echo "=== 3. rejected sign-in: generic message, detailed audit record ==="
run 1 "alice mistypes her password" "guess-it" login --user alice

echo "=== 4. accepted sign-in reaches admin functionality ==="
run 0 "alice signs in correctly" "$PW_ALICE" login --user alice

echo "=== 5. second administrator (needed later for break-glass unlock) ==="
# privileged add-user consumes two secrets in prompt order: authorising password, then new password
run 0 "alice authorises creation of bob" "$PW_ALICE
$PW_BOB" add-user bob --user alice

echo "=== 6. brute force across separate processes is throttled ==="
for i in 1 2 3 4 5; do
  printf 'guess-%s\n' "$i" | java -cp "$CP" adminportal.AdminPortal login --user alice $ITERS --home "$HOME_DIR" >/dev/null
done
echo "(five guesses spent in five separate JVMs)"
run 1 "correct password refused while alice is locked out" "$PW_ALICE" login --user alice

echo "=== 7. break-glass: an attacker cannot self-unlock, a peer administrator can ==="
run 1 "'unlock' with a wrong authorising password" "wrong" unlock alice --user bob
# (a locked administrator cannot lift their own lockout: unlock itself needs a valid login)
run 0 "bob authenticates and clears alice's lockout" "$PW_BOB" unlock alice --user bob
run 0 "alice can sign in again" "$PW_ALICE" login --user alice

echo "=== 8. reviewing the recorded events ==="
run 0 "the last six records" "$PW_ALICE" audit --user alice --limit 6
run 0 "aggregate summary" "$PW_ALICE" audit --user alice --summary --limit 100
run 0 "failures only, JSON for a SIEM" "$PW_ALICE" audit --user alice --failures-only --format json

echo "=== 9. integrity of the recorded events ==="
run 0 "verify-log on an intact trail" "" verify-log

echo "=== 10. tampering is detected ==="
python3 - "$HOME_DIR/audit-log.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
lines = open(p).read().splitlines(True)
for i, line in enumerate(lines):
    if '"outcome":"SUCCESS"' in line:
        seq = json.loads(line)["seq"]
        lines[i] = line.replace('"outcome":"SUCCESS"', '"outcome":"FAILURE"', 1)
        open(p, 'w').writelines(lines)
        print("(edited record seq=%s in place: SUCCESS -> FAILURE, hash left untouched)" % seq)
        break
else:
    print("(no SUCCESS record found -- demo needs one to tamper with)")
PY
run 1 "verify-log after the edit" "" verify-log

echo "=== 11. nothing secret on disk ==="
echo "grep for the password in every file written by the portal:"
if grep -rl "$PW_ALICE" "$HOME_DIR" >/dev/null 2>&1; then
  echo "  LEAK: the password appears in $HOME_DIR"
else
  echo "  no match in $HOME_DIR (only salted PBKDF2 digests are stored)"
fi
echo "stored credential line (alice only, digest truncated):"
grep '^alice|' "$HOME_DIR/administrators.dat" | cut -c1-72
echo "file permissions:"
ls -l "$HOME_DIR" | awk 'NR>1 {print "  " $1, $9}'
echo
echo "raw audit records (first two):"
head -2 "$HOME_DIR/audit-log.jsonl"
