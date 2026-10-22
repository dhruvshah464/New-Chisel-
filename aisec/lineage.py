"""Hash chain of sealed packs.

Each new run can record the manifest digest of the pack it was pinned against.
A model vendor's eval UI has no parent hash of *your* last independent test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import DEFAULT_RUNS_ROOT, load_json, manifest_digest, verify_manifest
from .pin import read_pin


def parent_of(run_dir: str | Path) -> dict[str, str] | None:
    target = load_json(Path(run_dir) / "target.json")
    digest = target.get("parent_manifest_sha256")
    if not digest:
        return None
    return {
        "run_id": str(target.get("parent_run_id") or ""),
        "manifest_sha256": str(digest),
    }


def find_by_digest(runs_root: str | Path, digest: str) -> Path | None:
    root = Path(runs_root)
    if not root.is_dir():
        return None
    for path in sorted(root.iterdir(), reverse=True):
        if not path.is_dir() or not (path / "manifest.json").is_file():
            continue
        if manifest_digest(path) == digest:
            return path
    return None


def walk_lineage(run_dir: str | Path, *, runs_root: str | Path = DEFAULT_RUNS_ROOT, limit: int = 32) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current: Path | None = run_dir
    while current is not None and len(chain) < limit:
        digest = manifest_digest(current)
        if digest in seen:
            chain.append({"run_id": current.name, "manifest_sha256": digest, "cycle": True})
            break
        seen.add(digest)
        verify_manifest(current)
        parent = parent_of(current)
        chain.append(
            {
                "run_id": current.name,
                "manifest_sha256": digest,
                "parent_manifest_sha256": (parent or {}).get("manifest_sha256"),
                "path": str(current),
            }
        )
        if not parent:
            break
        nxt = find_by_digest(runs_root, parent["manifest_sha256"])
        current = nxt
    return {
        "head": run_dir.name,
        "chain": chain,
        "complete": bool(chain) and chain[-1].get("parent_manifest_sha256") in (None, ""),
        "note": (
            "Each link is a sealed pack whose target.json names the previous manifest digest. "
            "A missing parent means the pin was not on disk, not that the hash is wrong."
        ),
    }


def render_lineage_markdown(lineage: dict[str, Any]) -> str:
    lines = ["# New Chisel evidence lineage", "", lineage["note"], ""]
    for i, link in enumerate(lineage["chain"]):
        prefix = "HEAD" if i == 0 else f"{i}"
        parent = link.get("parent_manifest_sha256") or "none"
        lines.append(f"{prefix}. `{link['run_id']}` `{link['manifest_sha256'][:12]}…` ← parent `{str(parent)[:12]}`")
        if link.get("cycle"):
            lines.append("Cycle detected; stopping.")
    if not lineage["complete"] and lineage["chain"]:
        lines.append("Chain is incomplete: a parent digest was recorded but that pack is not under --runs-root.")
    return "\n".join(lines) + "\n"


def pin_record(runs_root: str | Path) -> dict[str, str] | None:
    pin_file = Path(runs_root).resolve().parent / "baseline.json"
    if not pin_file.is_file():
        return None
    try:
        parent_dir = read_pin(pin_file)
    except Exception:
        return None
    return {"run_id": parent_dir.name, "manifest_sha256": manifest_digest(parent_dir)}
