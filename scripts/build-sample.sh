#!/usr/bin/env bash
# Rebuild the published sample in site/sample/: the demo agent, vulnerable variant, then fixed.
#
# With ANTHROPIC_API_KEY set, a Claude model drives the agent (REPEAT trials per scenario,
# default 3; AISEC_MODEL picks the model). Without it, the scripted replay stands in for the
# agent, and the reports say so.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  mode=(--repeat "${REPEAT:-3}")
else
  echo "ANTHROPIC_API_KEY is not set: building a replay-only sample (no model)." >&2
  mode=(--replay-only)
fi

runs="$(mktemp -d)"
trap 'rm -rf "$runs"' EXIT

for variant in vulnerable fixed; do
  status=0
  uv run aisec run --target demo --variant "$variant" --scenarios scenarios/support-agent \
    "${mode[@]}" --runs-root "$runs/$variant" || status=$?
  # 1 (an attack landed) and 2 (inconclusive) are results worth publishing; 3+ is an error.
  if [ "$status" -gt 2 ]; then
    echo "aisec run failed for the $variant variant (exit $status)" >&2
    exit "$status"
  fi
done

rm -rf site/sample
mkdir -p site/sample
for variant in vulnerable fixed; do
  pack="$(find "$runs/$variant" -mindepth 1 -maxdepth 1 -type d)"
  cp -R "$pack" "site/sample/$variant"
  uv run aisec verify "site/sample/$variant"
done
echo "Published site/sample/vulnerable/report.html and site/sample/fixed/report.html"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "Now update the sample section of site/index.html to match: the verdict counts and the 'How this sample was made' note." >&2
fi
