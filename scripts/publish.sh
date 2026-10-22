#!/bin/sh
# Build a PyPI artifact for aisec 0.1.0. Does not upload unless you pass --upload
# and have UV_PUBLISH_TOKEN set. Never uses an employer identity.
set -eu
cd "$(dirname "$0")/.."
uv build
echo "Wheels in dist/. To publish from a personal account:"
echo "  UV_PUBLISH_TOKEN=… uv publish"
if [ "${1:-}" = "--upload" ]; then
  uv publish
fi
