"""Pin a sealed pack as the local baseline.

CI and `aisec policy` can then fail regressions and tool drift without the operator
re-passing paths. The pin stores the path and the manifest digest, so a swapped folder
does not silently become the baseline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evidence import IntegrityError, DEFAULT_RUNS_ROOT, manifest_digest, now, verify_manifest

DEFAULT_PIN = Path(".aisec") / "baseline.json"


def default_pin_path(runs_root: str | Path = DEFAULT_RUNS_ROOT) -> Path:
    return Path(runs_root).resolve().parent / "baseline.json"


def write_pin(run_dir: str | Path, pin_path: str | Path = DEFAULT_PIN) -> dict[str, Any]:
    run_dir = Path(run_dir).resolve()
    verify_manifest(run_dir)
    payload = {
        "run_id": run_dir.name,
        "path": str(run_dir),
        "manifest_sha256": manifest_digest(run_dir),
        "pinned_at": now(),
    }
    pin_path = Path(pin_path)
    pin_path.parent.mkdir(parents=True, exist_ok=True)
    pin_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def read_pin(pin_path: str | Path = DEFAULT_PIN) -> Path | None:
    pin_path = Path(pin_path)
    if not pin_path.is_file():
        return None
    payload = json.loads(pin_path.read_text(encoding="utf-8"))
    path = Path(payload["path"])
    if not path.is_dir():
        raise IntegrityError(f"pinned baseline {path} is missing")
    verify_manifest(path)
    expected = payload.get("manifest_sha256")
    actual = manifest_digest(path)
    if expected and expected != actual:
        raise IntegrityError(f"pinned baseline {path} no longer matches digest {expected}")
    return path


def resolve_baseline(explicit: str | Path | None, *, runs_root: str | Path = DEFAULT_RUNS_ROOT) -> Path | None:
    if explicit:
        path = Path(explicit)
        if path.is_dir():
            return path
        under = Path(runs_root) / str(explicit)
        if under.is_dir():
            return under
        raise IntegrityError(f"no baseline pack at {explicit}")
    return read_pin()
