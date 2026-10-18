#!/bin/bash
# Manual smoke run of the delivered command line, against a throwaway H2 server.
# Usage: bash smoke.sh <dir-with-build-and-schema.sql> <h2.jar>
set -u
DIR="${1:?dir}"
JAR="${2:?h2 jar}"
PORT=$(( 20000 + (RANDOM % 20000) ))
LOG="$DIR/.qwen/tmp/smoke.log"
CP="$DIR/build:$JAR"

java -cp "$JAR" org.h2.tools.Server -tcp -tcpPort "$PORT" -ifNotExists >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
for _ in $(seq 1 60); do
  (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
  sleep 0.2
done

URL="jdbc:h2:tcp://127.0.0.1:$PORT/mem:demo;DB_CLOSE_DELAY=-1"
{
  echo "=== 1. create the table ==="
  java -cp "$CP" org.h2.tools.RunScript -url "$URL" -user sa -script "$DIR/schema.sql"
  echo "(exit $?)"

  echo
  echo "=== 2. register an account (password typed once, never shown) ==="
  printf 'Sunny-Evening-42\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa add-user --email you@example.com
  echo "(exit $?)"

  echo
  echo "=== 3. correct credential ==="
  printf 'Sunny-Evening-42\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa --email you@example.com
  echo "(exit $?)"

  echo
  echo "=== 4. wrong password ==="
  printf 'Sunny-Evening-43\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa --email you@example.com
  echo "(exit $?)"

  echo
  echo "=== 5. no such account ==="
  printf 'Sunny-Evening-42\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa --email nobody@example.com
  echo "(exit $?)"

  echo
  echo "=== 6. the classic injection payload ==="
  printf 'Sunny-Evening-42\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa "--email" "you@example.com' OR '1'='1"
  echo "(exit $?)"

  echo
  echo "=== 7. 'everything' payload ==="
  printf 'whatever\n' | java -cp "$CP" AuthenticationService \
      --jdbc "$URL" --user sa "--email" "' OR '1'='1"
  echo "(exit $?)"

  echo
  echo "=== 8. database unreachable (fail closed) ==="
  printf 'Sunny-Evening-42\n' | java -cp "$CP" AuthenticationService \
      --jdbc "jdbc:h2:tcp://127.0.0.1:1/mem:none" --user sa --email you@example.com
  echo "(exit $?)"

  echo
  echo "=== 9. the table and its one row survived ==="
  java -cp "$CP" org.h2.tools.RunScript -url "$URL" -user sa -showResults \
      -script /dev/stdin <<'SQL'
SELECT COUNT(*) AS rows_left FROM users;
SQL
} > "$LOG" 2>&1
echo "wrote $LOG"
