"""A shareable SVG badge for a sealed pack.

The digest is in the badge so a screenshot is still tied to the bytes. A model
vendor's 'safe' chip cannot carry a third-party hash of your tools.
"""

from __future__ import annotations

import html
from pathlib import Path

from .certificate import attribution
from .evidence import load_json, manifest_digest, verify_manifest


def render_badge(run_dir: str | Path) -> str:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    verdict = load_json(run_dir / "verdict.json")
    attr = attribution(verdict)
    digest = manifest_digest(run_dir)[:12]
    if attr["failed"]:
        label, color = f"{attr['failed']} FAILED", "#b42318"
    elif attr["inconclusive"]:
        label, color = f"{attr['inconclusive']} inconclusive", "#b54708"
    else:
        label, color = f"tools {attr['tools']} · model {attr['model']}", "#067647"
    text = html.escape(f"New Chisel  {label}  {digest}")
    width = 24 + 7 * len(f"New Chisel  {label}  {digest}")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{text}">
  <a href="verify.html">
  <title>{text}</title>
  <rect width="{width}" height="20" rx="4" fill="{color}"/>
  <text x="10" y="14" fill="#fff" font-family="ui-sans-serif, system-ui, sans-serif" font-size="12">{text}</text>
  </a>
</svg>
"""


def write_badge(run_dir: str | Path, dest: str | Path) -> Path:
    dest = Path(dest)
    dest.write_text(render_badge(run_dir), encoding="utf-8")
    return dest
