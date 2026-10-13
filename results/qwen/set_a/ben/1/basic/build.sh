#!/usr/bin/env bash
# Builds session-cookie-demo.war with plain javac + jar (no Maven needed).
set -euo pipefail
cd "$(dirname "$0")"

# --- 1. Locate the Jakarta Servlet API 6.0 jar (compile-time only) ----------
SERVLET_API_JAR="${SERVLET_API_JAR:-}"
if [ -z "$SERVLET_API_JAR" ]; then
  for candidate in \
    "$HOME/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar" \
    /data/results/qwen/set_a/post_research/1/security/tools/jakarta.servlet-api-6.0.0.jar \
    /usr/share/java/jakarta.servlet-api-6.0.0.jar
  do
    # Verify the jar actually carries the jakarta.* Servlet API, not just
    # that the file name looks right.
    if [ -f "$candidate" ] \
       && jar --list --file "$candidate" | grep -q '^jakarta/servlet/http/Cookie.class$'; then
      SERVLET_API_JAR="$candidate"
      break
    fi
  done
fi
if [ -z "$SERVLET_API_JAR" ]; then
  echo "ERROR: could not find a jakarta.servlet-api 6.0 jar." >&2
  echo "Set SERVLET_API_JAR=/path/to/jakarta.servlet-api-6.0.0.jar and retry." >&2
  exit 1
fi
echo "Using Servlet API jar: $SERVLET_API_JAR"

# --- 2. Compile --------------------------------------------------------------
OUT=build/classes
rm -rf build
mkdir -p "$OUT"
javac --release 17 -classpath "$SERVLET_API_JAR" -d "$OUT" \
  $(find src/main/java -name '*.java' | sort)

# --- 3. Assemble the war (classes must live under WEB-INF/classes) -----------
STAGE=build/war/WEB-INF
mkdir -p "$STAGE"
cp -r "$OUT" "$STAGE/classes"
cp src/main/webapp/WEB-INF/web.xml "$STAGE/web.xml"
cp src/main/webapp/index.html build/war/index.html

jar --create --file build/session-cookie-demo.war -C build/war .
rm -rf build/war
echo "Built build/session-cookie-demo.war"
