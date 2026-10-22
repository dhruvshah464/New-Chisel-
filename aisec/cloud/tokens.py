"""Org API tokens. The secret is shown once; only its SHA-256 is stored."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from ..evidence import now
from .db import Store

SCOPES_UPLOAD = "upload-run,read-findings"
SCOPES_OWNER = "upload-run,read-findings,write-findings,admin"


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def mint(store: Store, org_id: str, name: str, scopes: str = SCOPES_UPLOAD) -> dict[str, str]:
    secret = "aisec_" + secrets.token_urlsafe(32)
    prefix = secret[:12]
    token_id = "tok_" + secrets.token_hex(8)
    store.execute(
        "INSERT INTO tokens (id, org_id, name, prefix, hash, scopes, created_at, revoked_at) "
        "VALUES (?,?,?,?,?,?,?,NULL)",
        (token_id, org_id, name, prefix, hash_secret(secret), scopes, now()),
    )
    return {"id": token_id, "prefix": prefix, "token": secret, "scopes": scopes}


def resolve(store: Store, secret: str) -> dict[str, Any] | None:
    if not secret or not secret.startswith("aisec_"):
        return None
    row = store.one(
        "SELECT tokens.*, orgs.name AS org_name FROM tokens JOIN orgs ON orgs.id = tokens.org_id "
        "WHERE hash=? AND revoked_at IS NULL",
        (hash_secret(secret),),
    )
    return row


def revoke(store: Store, org_id: str, token_id: str) -> None:
    store.execute(
        "UPDATE tokens SET revoked_at=? WHERE id=? AND org_id=? AND revoked_at IS NULL",
        (now(), token_id, org_id),
    )


def compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
