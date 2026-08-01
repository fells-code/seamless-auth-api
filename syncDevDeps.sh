#!/bin/sh
# Installs node_modules when it does not match package-lock.json.
#
# The dev stack keeps node_modules in its own volume so the host tree, built for the
# host's platform, never reaches the container. That volume outlives `docker compose
# up --build`, so without this the container keeps running whatever was installed the
# first time it booted, however far package.json has moved on since.
#
# Also run at image build time, so a fresh volume inherits a stamp that matches what
# the image already installed and the first boot does not reinstall it.
set -eu

STAMP=node_modules/.package-lock-stamp
LOCK_HASH="$(md5sum package-lock.json | cut -d ' ' -f 1)"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$LOCK_HASH" ]; then
  echo "Dependencies match package-lock.json, skipping install."
  exit 0
fi

echo "Installing dependencies from package-lock.json..."
npm ci --no-audit --no-fund
printf '%s' "$LOCK_HASH" > "$STAMP"
