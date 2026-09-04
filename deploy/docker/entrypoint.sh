#!/usr/bin/env sh
# APP=<apps/ dir name> runs that service; anything else is passed through
# (used by the migrate and seed one-shots).
set -eu
if [ "$#" -gt 0 ]; then
  exec "$@"
fi
: "${APP:?set APP to an apps/<name> directory}"
cd "/app/apps/${APP}"
exec node --enable-source-maps dist/main.js
