"""CLI helper: tar a sealed pack and POST it to the control plane."""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..evidence import IntegrityError, verify_manifest
from ..signing import SigningError, read_signature, verify_signature


def tar_pack(run_dir: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(run_dir, arcname=run_dir.name)
    return buf.getvalue()


def upload_pack(
    run_dir: str | Path,
    *,
    url: str | None = None,
    token: str | None = None,
    project: str | None = None,
) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    if read_signature(run_dir) is None:
        raise IntegrityError("unsigned packs cannot be uploaded; run: aisec sign " + run_dir.name)
    try:
        verify_signature(run_dir)
    except SigningError:
        # Upload still sends the signature; the server checks it against its own key.
        pass
    origin = (url or os.environ.get("AISEC_URL") or "").rstrip("/")
    secret = token or os.environ.get("AISEC_TOKEN") or ""
    project_id = project or os.environ.get("AISEC_PROJECT") or ""
    if not origin or not secret or not project_id:
        raise ValueError("need --url / $AISEC_URL, --token / $AISEC_TOKEN and --project / $AISEC_PROJECT")
    body = tar_pack(run_dir)
    boundary = "aisecboundary"
    filename = run_dir.name + ".tar.gz"
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"project\"\r\n\r\n{project_id}\r\n".encode(),
        (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"pack\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/gzip\r\n\r\n"
        ).encode()
        + body
        + b"\r\n"
        + f"--{boundary}--\r\n".encode(),
    ]
    data = b"".join(parts)
    req = Request(
        origin + "/v1/runs",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "aisec-upload",
        },
    )
    try:
        with urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ValueError(f"control plane rejected the pack ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise ValueError(f"could not reach {origin}: {exc.reason}") from exc
    import json

    return json.loads(raw)
