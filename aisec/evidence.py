"""The sealed, write-once evidence pack.

One run of ``aisec run`` produces one directory under ``.aisec/runs/<run-id>/``:

    target.json        what was tested: target, variant, model, servers, canaries, versions
    scenarios/         the exact scenario files that ran
    events.jsonl       every tools/list and tools/call the proxy observed, per trial
    transcripts.jsonl  what the agent (or the replay) said and did, per trial
    sink.jsonl         side effects the synthetic servers recorded instead of performing
    checks.jsonl       each trial's check result
    verdict.json       per-scenario verdicts and the run summary
    report.md/.html    the human-readable report, rendered from the files above
    authorization.yaml the signed-off authorization (command target only), copied verbatim
    manifest.json      the SHA-256 of every other file; written last

Files are written once. ``seal()`` writes the manifest and makes every file read-only;
``verify_manifest()`` recomputes the hashes and fails on any missing, extra or changed
file. The manifest is not signed: it detects edits, not an attacker who also rewrites the
manifest. Record the manifest digest printed by ``aisec verify`` somewhere you trust (a
ticket, an email) to pin a pack.

Adapted from OpenTruth's run store (github.com/dhruvshah464/OpenTruth).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__

FROZEN_JSON = ("target.json", "verdict.json")
JSONL_FILES = ("events.jsonl", "transcripts.jsonl", "sink.jsonl", "checks.jsonl")
TEXT_FILES = ("report.md", "report.html", "report.sarif", "junit.xml")
SCENARIO_DIR = "scenarios"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "signature.json"
# Detached signature is written after freeze, so it is not in the manifest.
UNTRACKED = frozenset({SIGNATURE_NAME, "certificate.html", "attestation.json"})
DEFAULT_RUNS_ROOT = Path(".aisec") / "runs"


class EvidenceError(RuntimeError):
    pass


class IntegrityError(EvidenceError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_line(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RunStore:
    """Write-once evidence store. After ``seal()``, every file is hashed and read-only."""

    def __init__(self, runs_root: str | Path = DEFAULT_RUNS_ROOT, run_id: str | None = None):
        self.run_id = run_id or new_run_id()
        self.root = Path(runs_root) / self.run_id
        self.created_at = now()
        self.sealed = False

    def create(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root / SCENARIO_DIR).mkdir()
        for name in JSONL_FILES:
            (self.root / name).write_text("", encoding="utf-8")
        return self.root

    def write_json(self, name: str, obj: Any) -> Path:
        self._reject_if_sealed()
        if name not in FROZEN_JSON:
            raise EvidenceError(f"json file not in the pack schema: {name}")
        return self._write_once(self.root / name, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    def write_text(self, name: str, text: str) -> Path:
        self._reject_if_sealed()
        if name not in TEXT_FILES:
            raise EvidenceError(f"text file not in the pack schema: {name}")
        return self._write_once(self.root / name, text)

    def add_scenario(self, source: str | Path, scenario_id: str) -> str:
        self._reject_if_sealed()
        rel = f"{SCENARIO_DIR}/{scenario_id}.yaml"
        target = self.root / rel
        if target.exists():
            raise EvidenceError(f"{rel} already written")
        shutil.copyfile(source, target)
        return rel

    def add_file(self, name: str, source: str | Path) -> str:
        """Copy a target-supplied file (e.g. an authorization record) into the pack, verbatim."""
        self._reject_if_sealed()
        reserved = {*FROZEN_JSON, *JSONL_FILES, *TEXT_FILES, SCENARIO_DIR, MANIFEST_NAME}
        if not name or "/" in name or "\\" in name or name.startswith(".") or name in reserved:
            raise EvidenceError(f"not a valid extra evidence file name: {name!r}")
        target = self.root / name
        if target.exists():
            raise EvidenceError(f"{name} already written")
        shutil.copyfile(source, target)
        return name

    def append(self, name: str, record: dict[str, Any]) -> None:
        self._reject_if_sealed()
        if name not in JSONL_FILES:
            raise EvidenceError(f"not a jsonl file in the pack schema: {name}")
        with (self.root / name).open("a", encoding="utf-8") as handle:
            handle.write(_jsonl_line(record) + "\n")

    def extend(self, name: str, records: Iterable[dict[str, Any]]) -> None:
        for record in records:
            self.append(name, record)

    def seal(self) -> dict[str, Any]:
        self._reject_if_sealed()
        for required in FROZEN_JSON:
            if not (self.root / required).is_file():
                raise EvidenceError(f"cannot seal without {required}")
        manifest_path = self.root / MANIFEST_NAME
        if manifest_path.exists():
            raise EvidenceError(f"{MANIFEST_NAME} already exists")
        files = {
            path.relative_to(self.root).as_posix(): {"sha256": _sha256_file(path), "bytes": path.stat().st_size}
            for path in _iter_files(self.root)
        }
        manifest = {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "sealed_at": now(),
            "aisec_version": __version__,
            "sealed": True,
            "files": files,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.sealed = True
        _freeze_tree(self.root)
        return manifest

    def _write_once(self, path: Path, text: str) -> Path:
        if path.exists() and path.stat().st_size:
            raise EvidenceError(f"{path.name} already written")
        path.write_text(text, encoding="utf-8")
        return path

    def _reject_if_sealed(self) -> None:
        if self.sealed:
            raise EvidenceError("run is sealed; its records are immutable")


def _iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _freeze_tree(root: Path) -> None:
    for path in _iter_files(root):
        mode = path.stat().st_mode
        path.chmod(mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def manifest_digest(run_dir: str | Path) -> str:
    return _sha256_file(Path(run_dir) / MANIFEST_NAME)


def verify_manifest(run_dir: str | Path) -> dict[str, Any]:
    """Recompute every file hash; raise IntegrityError on any missing, extra or changed file."""
    run_dir = Path(run_dir)
    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise IntegrityError(f"missing {MANIFEST_NAME}; the run was never sealed")
    try:
        manifest = load_json(manifest_path)
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"{MANIFEST_NAME} is not valid JSON: {exc}") from exc
    if not manifest.get("sealed"):
        raise IntegrityError("run is not sealed")
    expected = {rel: meta["sha256"] for rel, meta in (manifest.get("files") or {}).items()}
    actual = {
        path.relative_to(run_dir).as_posix(): _sha256_file(path)
        for path in _iter_files(run_dir)
        if path != manifest_path and path.name not in UNTRACKED
    }
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(rel for rel in expected.keys() & actual.keys() if expected[rel] != actual[rel])
    if missing or extra or changed:
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"extra: {', '.join(extra)}")
        if changed:
            details.append(f"changed: {', '.join(changed)}")
        raise IntegrityError("; ".join(details))
    return manifest


def latest_run(runs_root: str | Path = DEFAULT_RUNS_ROOT) -> Path | None:
    runs_root = Path(runs_root)
    if not runs_root.is_dir():
        return None
    sealed = [p for p in runs_root.iterdir() if p.is_dir() and (p / MANIFEST_NAME).is_file()]
    return max(sealed, key=lambda p: p.name) if sealed else None


def resolve_run(ref: str, runs_root: str | Path = DEFAULT_RUNS_ROOT) -> Path:
    """Accept a run directory path, a run id under ``runs_root``, or ``latest``."""
    if ref == "latest":
        found = latest_run(runs_root)
        if found is None:
            raise EvidenceError(f"no sealed runs under {runs_root}")
        return found
    direct = Path(ref)
    if direct.is_dir():
        return direct
    under = Path(runs_root) / ref
    if under.is_dir():
        return under
    raise EvidenceError(f"no run directory {ref!r} (looked in . and {runs_root})")
