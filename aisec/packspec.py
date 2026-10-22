"""Open evidence-pack layout. Anyone can hash-check a pack without New Chisel's servers.

A model vendor will not publish a third-party notary format for someone else's agent.
This is that format: required files, untracked overlays, and a check that the sealed
layout is intact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import (
    FROZEN_JSON,
    JSONL_FILES,
    MANIFEST_NAME,
    TEXT_FILES,
    UNTRACKED,
    load_json,
    verify_manifest,
)

REQUIRED = (*FROZEN_JSON, *JSONL_FILES, MANIFEST_NAME)
EXPECTED_FROM_RUNNER = TEXT_FILES
OPTIONAL_IN_MANIFEST = ("authorization.yaml",)
UNTRACKED_OVERLAYS = tuple(sorted(UNTRACKED))


def layout() -> dict[str, Any]:
    return {
        "name": "New Chisel independent evidence pack",
        "version": "1",
        "issuer": "New Chisel, not a model vendor",
        "required": list(REQUIRED),
        "expected_from_runner": list(EXPECTED_FROM_RUNNER),
        "optional_in_manifest": list(OPTIONAL_IN_MANIFEST),
        "untracked_overlays": list(UNTRACKED_OVERLAYS),
        "note": (
            "Files in the manifest are hashed at seal. signature.json, certificate.html "
            "and attestation.json are written after seal so they can name the digest. "
            "Verify with SHA-256 of every manifest file; do not trust the overlay without "
            "recomputing that digest."
        ),
    }


def render_spec_markdown() -> str:
    spec = layout()
    lines = [
        "# New Chisel evidence pack spec",
        "",
        spec["note"],
        "",
        "Required (hashed in manifest.json):",
    ]
    for name in spec["required"]:
        lines.append(f"- `{name}`")
    lines += ["", "Written by `aisec run` (hashed):"]
    for name in spec["expected_from_runner"]:
        lines.append(f"- `{name}`")
    lines += ["", "Optional, hashed when present:"]
    for name in spec["optional_in_manifest"]:
        lines.append(f"- `{name}`")
    lines += ["", "Untracked overlays (after seal; not in the manifest):"]
    for name in spec["untracked_overlays"]:
        lines.append(f"- `{name}`")
    lines += ["", "Independent check: `aisec verify <run>` or the browser verifier.", ""]
    return "\n".join(lines)


def check_pack(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    missing = [name for name in REQUIRED if not (run_dir / name).is_file()]
    missing_expected = [name for name in EXPECTED_FROM_RUNNER if not (run_dir / name).is_file()]
    target = load_json(run_dir / "target.json")
    verdict = load_json(run_dir / "verdict.json")
    problems = list(missing)
    if "run_id" not in target and "run_id" not in verdict:
        problems.append("no run_id in target.json or verdict.json")
    if not isinstance(verdict.get("results"), list):
        problems.append("verdict.json has no results list")
    return {
        "ok": not problems,
        "problems": problems,
        "missing_expected": missing_expected,
        "layout": layout(),
    }
