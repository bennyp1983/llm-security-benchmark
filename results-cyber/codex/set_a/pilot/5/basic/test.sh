#!/usr/bin/env bash
set -euo pipefail

./build.sh
java -ea -cp out/main:out/test com.example.portal.AuthenticationTests
