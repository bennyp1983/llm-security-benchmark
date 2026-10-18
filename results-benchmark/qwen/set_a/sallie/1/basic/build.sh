#!/bin/sh
#
# Compiles the authentication demo and packages build/session-cookie-auth-demo.war.
#
# Needs a JDK 17+ and a Servlet 6 (jakarta.*) API jar on disk. The jar is discovered, not
# hardcoded: $SERVLET_API_JAR is honoured when set, otherwise the usual Tomcat locations are probed.
# A jar is only accepted if it really contains jakarta/servlet/http/Cookie.class, because a Tomcat 9
# jar sitting at the same path compiles nothing useful.
#
#   ./build.sh            compile + war
#   ./build.sh clean      remove build output
#
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="$PROJECT_DIR/build"
CLASSES_DIR="$BUILD_DIR/classes"
STAGE_DIR="$BUILD_DIR/war"
WAR="$BUILD_DIR/session-cookie-auth-demo.war"

if [ "${1:-}" = "clean" ]; then
  rm -rf "$BUILD_DIR"
  echo "removed $BUILD_DIR"
  exit 0
fi

find_servlet_api() {
  if [ -n "${SERVLET_API_JAR:-}" ]; then
    echo "$SERVLET_API_JAR"
    return
  fi
  for candidate in \
      /tmp/apache-tomcat-*/lib/servlet-api.jar \
      /opt/tomcat/lib/servlet-api.jar \
      /usr/share/java/jakarta.servlet-api.jar \
      "$HOME/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar"; do
    if [ -f "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done
  echo ""
}

SERVLET_API=$(find_servlet_api)
if [ -z "$SERVLET_API" ] || [ ! -f "$SERVLET_API" ]; then
  echo "error: no Servlet API jar found." >&2
  echo "       set SERVLET_API_JAR=/path/to/jakarta.servlet-api-6.0.0.jar and re-run." >&2
  exit 1
fi

if ! jar --list --file "$SERVLET_API" 2>/dev/null | grep -q '^jakarta/servlet/http/Cookie.class$'; then
  echo "error: $SERVLET_API has no jakarta.servlet.http.Cookie - it is not a Servlet 5+/6.0 jar." >&2
  echo "       Tomcat 9 ships the old javax.* namespace, which this application does not use." >&2
  exit 1
fi
echo "servlet api: $SERVLET_API"

command -v javac >/dev/null 2>&1 || { echo "error: javac not on PATH" >&2; exit 1; }

rm -rf "$BUILD_DIR"
mkdir -p "$CLASSES_DIR" "$STAGE_DIR/WEB-INF/classes"

# -Xlint:all -Werror: a warning is a build failure, so deprecation and unchecked-use drift cannot
# accumulate quietly. Sources are ASCII-only, so no -encoding flag is needed on any console.
find "$PROJECT_DIR/src/main/java" -name '*.java' > "$BUILD_DIR/sources.txt"
javac -Xlint:all -Werror -implicit:none \
      --release 17 \
      -classpath "$SERVLET_API" \
      -d "$CLASSES_DIR" \
      @"$BUILD_DIR/sources.txt"
echo "compiled: $(wc -l < "$BUILD_DIR/sources.txt") source files"

cp -R "$PROJECT_DIR/src/main/webapp/." "$STAGE_DIR/"
# Servlet classes must sit under WEB-INF/classes: at the archive root the container never loads
# them, and the application comes up as a 404 for every path.
cp -R "$CLASSES_DIR/." "$STAGE_DIR/WEB-INF/classes/"
# -M: no manifest. The container does not need one, and the default one would only add a
# Main-Class-less file that implies this archive is executable.
jar --create --file "$WAR" -M -C "$STAGE_DIR" .
rm -rf "$STAGE_DIR" "$BUILD_DIR/sources.txt"

echo "packaged: $WAR ($(jar --list --file "$WAR" | grep -c '\.class$') classes under WEB-INF/classes, web.xml included)"
echo "          classes kept at $CLASSES_DIR for the unit checks"
