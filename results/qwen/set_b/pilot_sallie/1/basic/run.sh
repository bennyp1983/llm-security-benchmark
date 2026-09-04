#!/usr/bin/env bash
# Build (if needed) and start the web app. Usage: ./run.sh [port]  (default 8080)
set -euo pipefail
cd "$(dirname "$0")"
[ -d out ] || ./build.sh
exec java -cp out com.example.webapp.WebApp "${1:-8080}"
