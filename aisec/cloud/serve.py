"""Run the control plane: ``aisec serve --data-dir .aisec/control``."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..signing import load_signing_key
from .app import create_app


def serve(*, host: str, port: int, data_dir: str, bootstrap: bool) -> int:
    os.environ.setdefault("AISEC_DATA_DIR", data_dir)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    if bootstrap:
        from fastapi.testclient import TestClient

        app = create_app(data_dir=data_dir, signing_key=load_signing_key() or b"aisec-dev-do-not-use-in-production")
        with TestClient(app) as client:
            response = client.post("/v1/bootstrap")
        print(json.dumps(response.json(), indent=2))
        return 0 if response.status_code in (200, 409) else 1
    try:
        import uvicorn
    except ImportError:
        print("aisec serve needs uvicorn; install with: uv sync --extra cloud")
        return 2
    url = f"http://{host}:{port}"
    print(f"New Chisel desk: {url}", flush=True)
    print("Open that address in a browser. If this machine is already bootstrapped, the desk unlocks itself.", flush=True)
    try:
        uvicorn.run(
            "aisec.cloud.app:create_app",
            factory=True,
            host=host,
            port=port,
            log_level="info",
        )
    except OSError as exc:
        print(f"aisec serve: could not bind {host}:{port} ({exc})", flush=True)
        print(f"If the desk is already running, open {url}. Stop the other process, or pick --port.", flush=True)
        return 1
    return 0
