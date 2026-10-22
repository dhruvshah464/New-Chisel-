"""New Chisel Independent Evidence Certificate.

A model vendor can grade its own model. It cannot issue a third-party record of
*your* agent that a buyer's reviewer can hash-check without trusting that vendor.
This certificate is that record: attribution (tools vs model), what was not
tested, the manifest digest, and the signature if present.
"""

from __future__ import annotations

import html
from typing import Any

from .report import _target_label, ordered
from .signing import read_signature
from .verdicts import FAILED, INCONCLUSIVE, RESISTED


def attribution(verdict: dict[str, Any]) -> dict[str, int]:
    counts = {"tools": 0, "model": 0, "failed": 0, "inconclusive": 0, "other": 0}
    for item in verdict.get("results") or []:
        if item.get("kind") != "attack":
            continue
        if item.get("verdict") == FAILED:
            counts["failed"] += 1
        elif item.get("verdict") == INCONCLUSIVE:
            counts["inconclusive"] += 1
        elif item.get("verdict") == RESISTED and item.get("resisted_by") == "tools":
            counts["tools"] += 1
        elif item.get("verdict") == RESISTED:
            counts["model"] += 1
        else:
            counts["other"] += 1
    return counts


def render_certificate(
    target: dict[str, Any],
    verdict: dict[str, Any],
    *,
    manifest_sha256: str = "",
    signature: dict[str, Any] | None = None,
) -> str:
    label = html.escape(_target_label(target))
    run_id = html.escape(str(target.get("run_id") or verdict.get("run_id") or ""))
    attr = attribution(verdict)
    attacks, _benign = ordered(verdict.get("results") or [])
    rows = []
    for item in attacks:
        who = item.get("resisted_by") or "—"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('id')))}</td>"
            f"<td>{html.escape(str(item.get('verdict')))}</td>"
            f"<td>{html.escape(str(who))}</td>"
            f"<td>{html.escape(str(item.get('severity') or ''))}</td>"
            "</tr>"
        )
    sig_line = "unsigned (hashed only)"
    if signature:
        sig_line = html.escape(f"{signature.get('alg')} · {signature.get('key_id')}")
    issuer = (
        "Issued by New Chisel, not by the model vendor. A vendor can tune a leaderboard "
        "for its own model. This certificate records what <em>this agent</em> did, from "
        "tool calls, with a reachability replay so a missing tool is not reported as safety."
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>New Chisel Independent Evidence · {run_id}</title>
<style>
 body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 820px; margin: 32px auto; color: #111; }}
 h1 {{ font-size: 22px; }} td, th {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; }}
 table {{ width: 100%; border-collapse: collapse; }} .box {{ border: 1px solid #ddd; padding: 12px 16px; }}
 code {{ background: #f4f4f4; padding: 1px 4px; }}
</style></head><body>
<p><strong>New Chisel</strong> · Independent Evidence Certificate</p>
<h1>{label}</h1>
<p>{issuer}</p>
<div class="box">
<p>Run <code>{run_id}</code></p>
<p>Manifest SHA-256 <code>{html.escape(manifest_sha256 or 'sealed with the pack')}</code></p>
<p>Signature: {sig_line}</p>
<p>Attacks stopped by tools: {attr['tools']} · by the model: {attr['model']} · landed: {attr['failed']} · inconclusive: {attr['inconclusive']}</p>
<p>Framework coverage below is what this pack judged. It is not an EU AI Act, ISO/IEC 42001, NIST, or AIUC-1 certification.</p>
</div>
<h2>Attacks</h2>
<table><thead><tr><th>Scenario</th><th>Verdict</th><th>Stopped by</th><th>Severity</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="4">None</td></tr>'}</tbody></table>
<p>Verify this pack: <code>aisec verify {run_id}</code> or drop the pack on the New Chisel verifier. Do not treat RESISTED as a guarantee.</p>
</body></html>
"""


CERTIFICATE_NAME = "certificate.html"


def certificate_for_dir(run_dir) -> str:
    from pathlib import Path

    from .evidence import load_json, manifest_digest

    run_dir = Path(run_dir)
    return render_certificate(
        load_json(run_dir / "target.json"),
        load_json(run_dir / "verdict.json"),
        manifest_sha256=manifest_digest(run_dir),
        signature=read_signature(run_dir),
    )


def write_certificate(run_dir) -> str:
    """Write the certificate next to the sealed pack. It is untracked, like signature.json."""
    from pathlib import Path

    run_dir = Path(run_dir)
    html = certificate_for_dir(run_dir)
    path = run_dir / CERTIFICATE_NAME
    if path.exists():
        path.chmod(path.stat().st_mode | 0o200)
    path.write_text(html, encoding="utf-8")
    path.chmod(path.stat().st_mode & ~0o222)
    return html
