"""Auditor bundle: one HTML packet a buyer can hand a reviewer.

The pack remains the evidence. This file is the cover sheet: issuer, attribution,
policy, tool drift, framework coverage (not a certification), and how to verify.
A model company will not issue this about someone else's agent.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .attestation import ATTESTATION_NAME, write_attestation
from .certificate import attribution, certificate_for_dir
from .compliance import coverage
from .drift import drift_packs
from .evidence import load_json, manifest_digest, verify_manifest
from .flow import flow_pack, render_flow_markdown
from .pin import resolve_baseline
from .policy import evaluate_policy, load_policy
from .report import _target_label
from .reproduce import reproduce_pack, render_reproduce_markdown
from .scope import render_scope_markdown, scope_pack
from .signing import read_signature
from .warrant import render_warrant_markdown, warrant_pack


def _esc(value: Any) -> str:
    return html.escape(str(value))


def render_bundle(
    run_dir: str | Path,
    *,
    policy_path: str | Path | None = None,
    baseline: str | Path | None = None,
) -> str:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    verdict = load_json(run_dir / "verdict.json")
    digest = manifest_digest(run_dir)
    sig = read_signature(run_dir)
    attr = attribution(verdict)
    spec = load_policy(policy_path)
    policy = evaluate_policy(run_dir, spec, baseline=baseline)
    base = resolve_baseline(baseline) if baseline else None
    drift = drift_packs(base, run_dir) if base is not None else None
    rows = []
    for clause in coverage(verdict):
        rows.append(
            "<tr>"
            f"<td>{_esc(clause['framework'])}</td>"
            f"<td>{_esc(clause['clause'])}</td>"
            f"<td>{_esc(clause['status'])}</td>"
            f"<td>{_esc(', '.join(clause['missing']) or '—')}</td>"
            "</tr>"
        )
    from .graph import graph_pack, render_graph_mermaid

    try:
        mermaid = render_graph_mermaid(graph_pack(run_dir))
        graph_html = f"<pre>{_esc(mermaid)}</pre>"
    except Exception:
        graph_html = "<p>No permission graph (event log empty or unreadable).</p>"
    flow = flow_pack(run_dir)
    flow_html = (
        f"<p>{_esc(len(flow['movements']))} movement(s); "
        f"{_esc(len(flow['exfiltrated']))} took effect through a tool argument or the sink. "
        f"Canaries that left: {_esc(', '.join(flow['exfiltrated_canaries']) or 'none')}.</p>"
    )
    warrant = warrant_pack(run_dir)
    warrant_html = (
        f"<p>Kind <code>{_esc(warrant['kind'])}</code> · "
        f"{'OK' if warrant['ok'] else 'FAIL'} · "
        f"inside window: {_esc(warrant.get('inside_window'))}.</p>"
    )
    if warrant.get("problems"):
        warrant_html += "<ul>" + "".join(f"<li>{_esc(p)}</li>" for p in warrant["problems"]) + "</ul>"
    scope = scope_pack(run_dir)
    scope_html = (
        f"<p>Unused: {_esc(len(scope['unused']))} · "
        f"shadow: {_esc(len(scope['shadow']))} · "
        f"{'OK' if scope['ok'] else 'FAIL'}.</p>"
    )
    recipe = reproduce_pack(run_dir)
    recipe_html = f"<pre>{_esc(recipe['command'])}</pre>"
    drift_html = "<p>No baseline pinned. <code>aisec pin</code> a pack to watch tool drift.</p>"
    if drift:
        if drift["ok"]:
            drift_html = "<p>No added, removed, or changed tools against the baseline.</p>"
        else:
            drift_html = (
                f"<p>Added: {_esc(', '.join(drift['added']) or '—')}. "
                f"Removed: {_esc(', '.join(drift['removed']) or '—')}. "
                f"Changed: {_esc(', '.join(drift['changed']) or '—')}.</p>"
            )
    violations = "".join(
        f"<li>{_esc(v['level'])} {_esc(v['code'])}: {_esc(v['detail'])}</li>" for v in policy["violations"]
    ) or "<li>No policy violations.</li>"
    sig_line = "unsigned (hashed only)"
    if sig:
        sig_line = f"{sig.get('alg')} · {sig.get('key_id')}"
    label = _esc(_target_label(target))
    run_id = _esc(target.get("run_id") or verdict.get("run_id") or run_dir.name)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>New Chisel auditor bundle · {run_id}</title>
<style>
 body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 860px; margin: 32px auto; color: #111; }}
 h1 {{ font-size: 22px; }} table {{ width: 100%; border-collapse: collapse; }}
 td, th {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; }}
 .box {{ border: 1px solid #ddd; padding: 12px 16px; }}
 .warn {{ background: #fffaeb; border: 1px solid #fedf89; padding: 12px 16px; }}
 code {{ background: #f4f4f4; padding: 1px 4px; }}
</style></head><body>
<p><strong>New Chisel</strong> · Auditor bundle (not a certification)</p>
<h1>{label}</h1>
<div class="warn">This is independent evidence about this agent, issued by New Chisel, not by a model vendor.
It is not an EU AI Act conformity assessment, not an ISO/IEC 42001 certificate, and not a guarantee.
Verify the sealed pack: <code>aisec verify {run_id}</code> — manifest SHA-256 <code>{_esc(digest)}</code>.</div>
<div class="box">
<p>Run <code>{run_id}</code></p>
<p>Signature: {_esc(sig_line)}</p>
<p>Stopped by tools: {attr['tools']} · by the model: {attr['model']} · landed: {attr['failed']} · inconclusive: {attr['inconclusive']}</p>
<p>Evidence policy: <strong>{'PASS' if policy['ok'] else 'FAIL'}</strong></p>
</div>
<h2>Policy</h2>
<ul>{violations}</ul>
<h2>Tool inventory drift</h2>
{drift_html}
<h2>Permission graph</h2>
<p>What the proxy recorded: listed, called, denied, held, injected. Not a runtime allow-list.</p>
{graph_html}
<h2>Framework coverage in this pack</h2>
<p>Covered means a scenario mapped to that clause was judged FAILED or RESISTED. Absent means this pack did not judge it.</p>
<table><thead><tr><th>Framework</th><th>Clause</th><th>Status</th><th>Missing ASI</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Canary data-flow</h2>
<p>Planted markers observed in tool arguments, the sink, or the agent's reply. Markers are not printed. This is not DLP.</p>
{flow_html}
<h2>Warrant</h2>
<p>Was this run authorized when it ran? Checked at <code>started_at</code>, not against the clock now. A model vendor has no customer-signed attack window.</p>
{warrant_html}
<h2>Tool scope</h2>
<p>Unused vs shadow tools from the proxy record. Not a runtime allow-list.</p>
{scope_html}
<h2>Reproduce</h2>
<p>Sealed recipe. Does not print API keys or server env values.</p>
{recipe_html}
<h2>Certificate</h2>
<p>The Independent Evidence Certificate for this pack (also at <code>certificate.html</code> in the pack):</p>
<iframe src="certificate.html" title="certificate" style="width:100%;min-height:360px;border:1px solid #ddd"></iframe>
</body></html>
"""


def write_bundle(
    run_dir: str | Path,
    dest: str | Path,
    *,
    policy_path: str | Path | None = None,
    baseline: str | Path | None = None,
) -> Path:
    run_dir = Path(run_dir)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "index.html").write_text(
        render_bundle(run_dir, policy_path=policy_path, baseline=baseline),
        encoding="utf-8",
    )
    (dest / "certificate.html").write_text(certificate_for_dir(run_dir), encoding="utf-8")
    from .badge import write_badge
    from .graph import graph_pack, render_graph_markdown

    write_badge(run_dir, dest / "badge.svg")
    (dest / "graph.md").write_text(render_graph_markdown(graph_pack(run_dir)), encoding="utf-8")
    (dest / "flow.md").write_text(render_flow_markdown(flow_pack(run_dir)), encoding="utf-8")
    (dest / "warrant.md").write_text(render_warrant_markdown(warrant_pack(run_dir)), encoding="utf-8")
    (dest / "scope.md").write_text(render_scope_markdown(scope_pack(run_dir)), encoding="utf-8")
    (dest / "reproduce.md").write_text(render_reproduce_markdown(reproduce_pack(run_dir)), encoding="utf-8")
    attest_src = run_dir / ATTESTATION_NAME
    if not attest_src.is_file():
        write_attestation(run_dir)
    (dest / ATTESTATION_NAME).write_text(attest_src.read_text(encoding="utf-8"), encoding="utf-8")
    return dest
