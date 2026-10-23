"""Sign and verify sealed evidence packs.

The manifest is hashed; a detached ``signature.json`` covers that digest.
Unsigned packs remain valid locally (``aisec verify`` still checks file hashes).
The hosted control plane refuses unsigned packs.

Signing key: the raw or hex secret in ``AISEC_SIGNING_KEY``, or a file at
``AISEC_SIGNING_KEY_FILE``. Algorithm: HMAC-SHA256 (stdlib; no extra dependency).
``key_id`` is the SHA-256 of the key, so verifiers can tell which key was used
without storing the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .evidence import IntegrityError, now, verify_manifest

SIGNATURE_NAME = "signature.json"
ALG = "hmac-sha256"
ENV_KEY = "AISEC_SIGNING_KEY"
ENV_KEY_FILE = "AISEC_SIGNING_KEY_FILE"


class SigningError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_signing_key() -> bytes | None:
    path = os.environ.get(ENV_KEY_FILE, "").strip()
    if path:
        return Path(path).read_bytes().strip()
    raw = os.environ.get(ENV_KEY, "")
    if not raw:
        return None
    raw = raw.strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def key_id(key: bytes) -> str:
    return "sha256:" + _sha256_bytes(key)


def generate_key() -> bytes:
    return os.urandom(32)


def _manifest_bytes(run_dir: Path) -> bytes:
    return (run_dir / "manifest.json").read_bytes()


def sign_pack(run_dir: str | Path, key: bytes | None = None) -> dict[str, Any] | None:
    """Write ``signature.json`` next to the manifest. No-op (returns None) without a key."""
    run_dir = Path(run_dir)
    key = load_signing_key() if key is None else key
    if key is None:
        return None
    verify_manifest(run_dir)
    digest = _sha256_bytes(_manifest_bytes(run_dir))
    signature = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
    payload = {
        "alg": ALG,
        "key_id": key_id(key),
        "manifest_sha256": digest,
        "signature": signature,
        "signed_at": now(),
    }
    path = run_dir / SIGNATURE_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(path.stat().st_mode & ~0o222)
    return payload


def read_signature(run_dir: str | Path) -> dict[str, Any] | None:
    path = Path(run_dir) / SIGNATURE_NAME
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def inspect_signature(run_dir: str | Path, key: bytes | None = None) -> dict[str, Any] | None:
    """Nested HMAC overlay. Never flips the reviewer hash pass. ``None`` if unsigned."""
    run_dir = Path(run_dir)
    payload = read_signature(run_dir)
    if payload is None:
        return None
    report = {
        "ok": False,
        "alg": payload.get("alg") or ALG,
        "key_id": payload.get("key_id") or "",
        "error": None,
    }
    if payload.get("alg") != ALG:
        report["error"] = "alg_unsupported"
        return report
    key = load_signing_key() if key is None else key
    if key is None:
        report["error"] = "key_missing"
        return report
    if payload.get("key_id") != key_id(key):
        report["error"] = "key_id_mismatch"
        return report
    digest = _sha256_bytes(_manifest_bytes(run_dir))
    if payload.get("manifest_sha256") != digest:
        report["error"] = "manifest_digest_mismatch"
        return report
    expected = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(payload.get("signature") or "")):
        report["error"] = "hmac_mismatch"
        return report
    report["ok"] = True
    return report


def verify_signature(run_dir: str | Path, key: bytes | None = None) -> dict[str, Any]:
    """Require a valid signature. Raises IntegrityError if missing or wrong."""
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    payload = read_signature(run_dir)
    if payload is None:
        raise IntegrityError("missing signature.json; this pack is hashed but not signed")
    if payload.get("alg") != ALG:
        raise IntegrityError(f"unsupported signature alg {payload.get('alg')!r}")
    key = load_signing_key() if key is None else key
    if key is None:
        raise SigningError(
            f"pack is signed by {payload.get('key_id')}; set {ENV_KEY} or {ENV_KEY_FILE} to verify the signature"
        )
    if payload.get("key_id") != key_id(key):
        raise IntegrityError("signature key_id does not match the configured signing key")
    digest = _sha256_bytes(_manifest_bytes(run_dir))
    if payload.get("manifest_sha256") != digest:
        raise IntegrityError("signature.json does not cover the current manifest")
    expected = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(payload.get("signature") or "")):
        raise IntegrityError("signature.json does not verify")
    return payload
