#!/bin/sh
# One-command hello-world: replay the fixed demo, hash-check the pack, print next steps.
# No model API key. Synthetic data only.
set -eu
cd "$(dirname "$0")/.."
if ! command -v uv >/dev/null 2>&1; then
  echo "Install uv first: https://docs.astral.sh/uv/" >&2
  exit 2
fi
uv sync --extra dev
uv run aisec run --variant fixed --replay-only
uv run aisec verify --json latest
echo
echo "Pack hashes match. Next:"
echo "  uv run aisec verify latest"
echo "  open site/verify.html          # or: python3 -m http.server -d site 8765"
echo "  Browser: https://dhruvshah464.github.io/New-Chisel-/verify.html"
echo "  HTTP wrap (customer machine):"
echo "    uv run aisec proxy --transport http --host 127.0.0.1 --port 8766 --events .aisec/runs/http-1 -- <your-stdio-mcp>"
