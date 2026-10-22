"""Machine-readable Independent Evidence attestation for GRC / SIEM / an insurer.

A model vendor's safety card is not an ingestible third-party record of your agent.
This JSON names the issuer, the digest, attribution (tools vs model), the parent
pack, and that it is not a certification. It is untracked, like certificate.html,
so it can include the manifest digest after seal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .certificate import attribution
from .evidence import load_json, manifest_digest, now, verify_manifest
from .flow import flow_pack
from .signing import read_signature

ATTESTATION_NAME = "attestation.json"
ATTESTATION_TYPE = "new-chisel.attestation.v1"


def render_attestation(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    verdict = load_json(run_dir / "verdict.json")
    sig = read_signature(run_dir)
    from .scope import scope_pack
    from .warrant import warrant_pack

    flow = flow_pack(run_dir)
    warrant = warrant_pack(run_dir)
    scope = scope_pack(run_dir)
    return {
        "type": ATTESTATION_TYPE,
        "issuer": "New Chisel",
        "not_a_certification": True,
        "not_issued_by_a_model_vendor": True,
        "aisec_version": target.get("aisec_version") or __version__,
        "run_id": target.get("run_id") or verdict.get("run_id") or run_dir.name,
        "started_at": target.get("started_at"),
        "driver": target.get("driver"),
        "manifest_sha256": manifest_digest(run_dir),
        "tool_list_sha256": target.get("tool_list_sha256"),
        "parent_manifest_sha256": target.get("parent_manifest_sha256"),
        "signed": bool(sig),
        "key_id": (sig or {}).get("key_id"),
        "attribution": attribution(verdict),
        "canary_flow": {
            "planted": flow["canaries"],
            "exfiltrated": flow["exfiltrated_canaries"],
            "movement_count": len(flow["movements"]),
        },
        "warrant": {
            "ok": warrant["ok"],
            "kind": warrant["kind"],
            "inside_window": warrant.get("inside_window"),
        },
        "scope": {
            "unused": len(scope["unused"]),
            "shadow": len(scope["shadow"]),
        },
        "exit_code": (verdict.get("summary") or {}).get("exit_code"),
        "attested_at": now(),
        "verify": f"aisec verify {run_dir.name}",
    }


def write_attestation(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    payload = render_attestation(run_dir)
    path = run_dir / ATTESTATION_NAME
    if path.exists():
        path.chmod(path.stat().st_mode | 0o200)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(path.stat().st_mode & ~0o222)
    return payload
