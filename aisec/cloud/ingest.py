"""Accept a sealed pack tarball, verify it, store it, open finding tickets."""

from __future__ import annotations

import os
import secrets
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from ..evidence import manifest_digest, now
from .db import Store
from .findings import sync_from_verdict
from .security import IngestRefused, dumps, inspect_pack


def _id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(8)


def extract_tar(data: bytes, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    tmp = dest / ".incoming.tar.gz"
    tmp.write_bytes(data)
    with tarfile.open(tmp, "r:*") as tar:
        _extract_safe(tar, dest)
    tmp.unlink(missing_ok=True)
    # The tarball is the run directory itself, or a wrapper with one child dir.
    if (dest / "manifest.json").is_file():
        return dest
    children = [p for p in dest.iterdir() if p.is_dir()]
    if len(children) == 1 and (children[0] / "manifest.json").is_file():
        return children[0]
    raise IngestRefused("tarball has no sealed evidence pack (missing manifest.json)")


def _extract_safe(tar: tarfile.TarFile, dest: Path) -> None:
    for member in tar.getmembers():
        name = Path(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise IngestRefused(f"refusing path in tarball: {member.name}")
        kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        tar.extract(member, dest, **kwargs)


def store_pack(src: Path, packs_root: Path, org_id: str, project_id: str, run_id: str) -> Path:
    target = packs_root / org_id / project_id / run_id
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, target)
    for path in target.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o400)
    return target


def ingest(
    store: Store,
    *,
    org_id: str,
    project_id: str,
    blob: bytes,
    packs_root: Path,
    signing_key: bytes,
    actor: str,
) -> dict[str, Any]:
    project = store.one("SELECT * FROM projects WHERE id=? AND org_id=?", (project_id, org_id))
    if project is None:
        raise IngestRefused("unknown project for this organization")
    with tempfile.TemporaryDirectory(prefix="aisec-ingest-") as tmp:
        run_dir = extract_tar(blob, Path(tmp) / "pack")
        inspected = inspect_pack(run_dir, signing_key=signing_key)
        run_id = inspected["verdict"].get("run_id") or run_dir.name
        digest = manifest_digest(run_dir)
        existing = store.one(
            "SELECT * FROM runs WHERE org_id=? AND run_id=? AND manifest_sha256=?",
            (org_id, run_id, digest),
        )
        if existing:
            return {"run_id": run_id, "id": existing["id"], "duplicate": True, "findings_opened": 0}
        packed = store_pack(run_dir, packs_root, org_id, project_id, run_id)
        row_id = _id("run")
        summary = dumps((inspected["verdict"].get("summary") or {}))
        store.execute(
            "INSERT INTO runs (id, org_id, project_id, run_id, manifest_sha256, pack_path, summary, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (row_id, org_id, project_id, run_id, digest, str(packed), summary, now()),
        )
        counts = sync_from_verdict(
            store,
            org_id=org_id,
            project_id=project_id,
            run_id=run_id,
            verdict=inspected["verdict"],
            actor=actor,
        )
        store.execute(
            "INSERT INTO audit (id, org_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            (_id("aud"), org_id, actor, "pack.upload", dumps({"run_id": run_id, "sha256": digest}), now()),
        )
        return {
            "id": row_id,
            "run_id": run_id,
            "manifest_sha256": digest,
            "duplicate": False,
            "findings_opened": counts["opened"],
            "findings_updated": counts["updated"],
            "findings_resolved": counts["resolved"],
        }
