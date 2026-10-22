"""Ingest gates: no production, no live data, no leftover secrets, signed packs only."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..evidence import IntegrityError, load_json, verify_manifest
from ..redact import KEY_SHAPED, PEM
from ..signing import read_signature, verify_signature
from ..targets.command import DATA_KINDS

PROD = re.compile(r"\bprod", re.IGNORECASE)
ENV_VALUE_KEYS = {"env", "secrets", "environment_variables"}


class IngestRefused(ValueError):
    pass


def scan_for_secrets(run_dir: Path) -> list[str]:
    hits: list[str] = []
    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if PEM.search(text) or KEY_SHAPED.search(text):
            hits.append(path.name)
    return sorted(set(hits))


def recorded_env_values(value: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).lower() in ENV_VALUE_KEYS and isinstance(item, dict):
                if any(isinstance(v, str) and v for v in item.values()):
                    hits.append(here)
            hits.extend(recorded_env_values(item, here))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            hits.extend(recorded_env_values(item, f"{path}[{i}]"))
    return hits


def refuse_live_target(target: dict[str, Any]) -> None:
    described = target.get("target") or {}
    auth = described.get("authorization") or {}
    environment = str(auth.get("environment") or "")
    data = str(auth.get("data") or "")
    if environment and PROD.search(environment):
        raise IngestRefused(f"scope.environment is {environment!r}: production packs are never stored")
    if data and data not in DATA_KINDS:
        raise IngestRefused(f"data is {data!r}: only synthetic or sanitized packs may be uploaded")


def inspect_pack(run_dir: Path, *, signing_key: bytes | None) -> dict[str, Any]:
    verify_manifest(run_dir)
    if signing_key is None or read_signature(run_dir) is None:
        raise IngestRefused("unsigned packs cannot be uploaded; sign with AISEC_SIGNING_KEY")
    try:
        verify_signature(run_dir, key=signing_key)
    except IntegrityError as exc:
        raise IngestRefused(str(exc)) from exc
    secrets = scan_for_secrets(run_dir)
    if secrets:
        raise IngestRefused(f"pack still contains secret-looking values in {', '.join(secrets)}")
    target = load_json(run_dir / "target.json")
    refuse_live_target(target)
    env_hits = recorded_env_values(target)
    if env_hits:
        raise IngestRefused(f"target.json looks like it recorded env values at {', '.join(env_hits[:5])}")
    verdict = load_json(run_dir / "verdict.json")
    return {"target": target, "verdict": verdict}


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)
