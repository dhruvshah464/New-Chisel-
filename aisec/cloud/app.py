"""FastAPI control plane. No agent execution. Packs stay per-org on disk."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import tempfile

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..evidence import now
from .db import Store
from .export_issues import export_github, export_linear
from .findings import assign, comment, retest_snippet, set_status
from .ingest import IngestRefused, ingest
from .security import dumps
from .tokens import SCOPES_OWNER, mint, resolve, revoke

_HERE = Path(__file__).resolve().parent
WEB_DIR = next(
    (p for p in (_HERE / "web", _HERE.parents[1] / "apps" / "web") if (p / "index.html").is_file()),
    _HERE / "web",
)
OWNER_TOKEN_NAME = "owner.token"


def _write_owner_token(data_dir: Path, token: str) -> None:
    path = Path(data_dir) / OWNER_TOKEN_NAME
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)


class State:
    def __init__(self, data_dir: Path, signing_key: bytes):
        self.data_dir = data_dir
        self.packs = data_dir / "packs"
        self.packs.mkdir(parents=True, exist_ok=True)
        self.store = Store(data_dir / "control.db")
        self.signing_key = signing_key


def create_app(data_dir: str | Path | None = None, signing_key: bytes | None = None) -> FastAPI:
    data_dir = Path(data_dir or os.environ.get("AISEC_DATA_DIR") or ".aisec/control")
    if signing_key is None:
        from ..signing import load_signing_key

        signing_key = load_signing_key()
        if signing_key is None:
            # Local-only fallback so `aisec serve` works; production must set AISEC_SIGNING_KEY.
            signing_key = b"aisec-dev-do-not-use-in-production"
    state = State(Path(data_dir), signing_key)

    app = FastAPI(title="New Chisel", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.ctl = state
    app.add_middleware(SecurityHeaders)

    def ctl() -> State:
        return app.state.ctl

    def auth(
        request: Request,
        authorization: str | None = Header(default=None),
        x_aisec_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        secret = None
        if authorization and authorization.lower().startswith("bearer "):
            secret = authorization.split(" ", 1)[1].strip()
        elif x_aisec_token:
            secret = x_aisec_token.strip()
        elif request.cookies.get("aisec_session"):
            secret = request.cookies["aisec_session"]
        if not secret:
            raise HTTPException(401, "missing bearer token")
        row = resolve(ctl().store, secret)
        if row is None:
            raise HTTPException(401, "invalid or revoked token")
        return row

    def require(scope: str):
        def inner(principal: dict[str, Any] = Depends(auth)) -> dict[str, Any]:
            scopes = {s.strip() for s in str(principal.get("scopes") or "").split(",") if s.strip()}
            if scope not in scopes and "admin" not in scopes:
                raise HTTPException(403, f"token missing scope {scope}")
            return principal

        return inner

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/bootstrap")
    def bootstrap() -> dict[str, Any]:
        if ctl().store.one("SELECT id FROM orgs LIMIT 1"):
            raise HTTPException(409, "already bootstrapped")
        org_id = "org_" + secrets.token_hex(8)
        project_id = "prj_" + secrets.token_hex(8)
        ctl().store.execute("INSERT INTO orgs (id, name, created_at) VALUES (?,?,?)", (org_id, "local", now()))
        ctl().store.execute(
            "INSERT INTO projects (id, org_id, name, created_at) VALUES (?,?,?,?)",
            (project_id, org_id, "default", now()),
        )
        token = mint(ctl().store, org_id, "owner", SCOPES_OWNER)
        ctl().store.execute(
            "INSERT INTO audit (id, org_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            ("aud_" + secrets.token_hex(8), org_id, "bootstrap", "org.create", dumps({"project_id": project_id}), now()),
        )
        _write_owner_token(ctl().data_dir, token["token"])
        return {"org_id": org_id, "project_id": project_id, "token": token["token"], "prefix": token["prefix"]}

    def _loopback(request: Request) -> bool:
        host = (request.client.host if request.client else "") or ""
        return host in {"127.0.0.1", "::1", "localhost", "testclient"}

    def _raw_token(request: Request) -> str:
        authorization = request.headers.get("authorization") or ""
        if authorization.lower().startswith("bearer "):
            return authorization.split(" ", 1)[1].strip()
        return request.headers.get("x-aisec-token") or request.cookies.get("aisec_session") or ""

    @app.post("/v1/session")
    def create_session(request: Request, principal: dict[str, Any] = Depends(auth)) -> JSONResponse:
        response = JSONResponse({"ok": True, "org_id": principal["org_id"]})
        response.set_cookie(
            "aisec_session",
            _raw_token(request),
            httponly=True,
            samesite="strict",
            secure=False,
            max_age=60 * 60 * 12,
        )
        return response

    @app.post("/v1/local-unlock")
    def local_unlock(request: Request) -> JSONResponse:
        """Open the desk from this machine without pasting a token. Loopback only."""
        if not _loopback(request):
            raise HTTPException(403, "local unlock is only for this machine")
        path = ctl().data_dir / OWNER_TOKEN_NAME
        if not path.is_file():
            raise HTTPException(404, "this machine has not been bootstrapped yet")
        secret = path.read_text(encoding="utf-8").strip()
        row = resolve(ctl().store, secret)
        if row is None:
            raise HTTPException(401, "local owner token is invalid or revoked")
        response = JSONResponse({"ok": True, "org_id": row["org_id"], "token": secret, "prefix": row["prefix"]})
        response.set_cookie(
            "aisec_session",
            secret,
            httponly=True,
            samesite="strict",
            secure=False,
            max_age=60 * 60 * 12,
        )
        return response

    @app.get("/v1/me")
    def me(principal: dict[str, Any] = Depends(auth)) -> dict[str, Any]:
        projects = ctl().store.query(
            "SELECT id, name, created_at FROM projects WHERE org_id=? ORDER BY name",
            (principal["org_id"],),
        )
        return {
            "org_id": principal["org_id"],
            "org_name": principal["org_name"],
            "token_prefix": principal["prefix"],
            "scopes": principal["scopes"],
            "projects": projects,
        }

    @app.post("/v1/projects")
    def create_project(name: str = Form(...), principal: dict[str, Any] = Depends(require("admin"))) -> dict[str, Any]:
        project_id = "prj_" + secrets.token_hex(8)
        try:
            ctl().store.execute(
                "INSERT INTO projects (id, org_id, name, created_at) VALUES (?,?,?,?)",
                (project_id, principal["org_id"], name.strip(), now()),
            )
        except Exception as exc:
            raise HTTPException(409, "project name already exists") from exc
        return {"id": project_id, "name": name.strip()}

    @app.post("/v1/tokens")
    def create_token(
        name: str = Form("ci"),
        scopes: str = Form("upload-run,read-findings"),
        principal: dict[str, Any] = Depends(require("admin")),
    ) -> dict[str, Any]:
        token = mint(ctl().store, principal["org_id"], name, scopes)
        ctl().store.execute(
            "INSERT INTO audit (id, org_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            (
                "aud_" + secrets.token_hex(8),
                principal["org_id"],
                principal["prefix"],
                "token.create",
                dumps({"id": token["id"], "prefix": token["prefix"]}),
                now(),
            ),
        )
        return token

    @app.post("/v1/tokens/{token_id}/revoke")
    def revoke_token(token_id: str, principal: dict[str, Any] = Depends(require("admin"))) -> dict[str, str]:
        revoke(ctl().store, principal["org_id"], token_id)
        ctl().store.execute(
            "INSERT INTO audit (id, org_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            (
                "aud_" + secrets.token_hex(8),
                principal["org_id"],
                principal["prefix"],
                "token.revoke",
                dumps({"id": token_id}),
                now(),
            ),
        )
        return {"status": "revoked"}

    @app.post("/v1/runs")
    async def upload_run(
        project: str = Form(...),
        pack: UploadFile = File(...),
        principal: dict[str, Any] = Depends(require("upload-run")),
    ) -> dict[str, Any]:
        blob = await pack.read()
        if len(blob) > 50 * 1024 * 1024:
            raise HTTPException(413, "pack larger than 50 MiB")
        try:
            result = ingest(
                ctl().store,
                org_id=principal["org_id"],
                project_id=project,
                blob=blob,
                packs_root=ctl().packs,
                signing_key=ctl().signing_key,
                actor=principal["prefix"],
            )
        except IngestRefused as exc:
            raise HTTPException(400, str(exc)) from exc
        return result

    @app.post("/v1/public/verify")
    async def public_verify(pack: UploadFile = File(...)) -> dict[str, Any]:
        """Hash-check a pack without storing it. No login. HMAC is not required here."""
        from ..certificate import attribution
        from ..evidence import IntegrityError, load_json, manifest_digest, verify_manifest
        from ..signing import read_signature
        from .ingest import extract_tar

        blob = await pack.read()
        if len(blob) > 50 * 1024 * 1024:
            raise HTTPException(413, "pack larger than 50 MiB")
        with tempfile.TemporaryDirectory(prefix="aisec-verify-") as tmp:
            try:
                run_dir = extract_tar(blob, Path(tmp) / "pack")
                verify_manifest(run_dir)
            except Exception as exc:
                raise HTTPException(400, str(exc)) from exc
            verdict = load_json(run_dir / "verdict.json")
            target = load_json(run_dir / "target.json")
            sig = read_signature(run_dir)
            return {
                "ok": True,
                "issuer": "New Chisel Independent Evidence — not issued by a model vendor",
                "run_id": verdict.get("run_id") or target.get("run_id"),
                "manifest_sha256": manifest_digest(run_dir),
                "signed": bool(sig),
                "key_id": (sig or {}).get("key_id"),
                "attribution": attribution(verdict),
            }

    @app.get("/v1/runs")
    def list_runs(project: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> dict[str, Any]:
        rows = ctl().store.query(
            "SELECT id, run_id, manifest_sha256, summary, created_at FROM runs "
            "WHERE org_id=? AND project_id=? ORDER BY created_at DESC LIMIT 50",
            (principal["org_id"], project),
        )
        return {"runs": rows}

    @app.get("/v1/runs/{run_id}/report")
    def run_report(run_id: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> Response:
        row = ctl().store.one(
            "SELECT * FROM runs WHERE org_id=? AND run_id=?",
            (principal["org_id"], run_id),
        )
        if row is None:
            raise HTTPException(404, "unknown run")
        html = Path(row["pack_path"]) / "report.html"
        if not html.is_file():
            raise HTTPException(404, "report.html missing from pack")
        return FileResponse(html, media_type="text/html")

    @app.get("/v1/runs/{run_id}/certificate")
    def run_certificate(run_id: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> Response:
        row = ctl().store.one(
            "SELECT * FROM runs WHERE org_id=? AND run_id=?",
            (principal["org_id"], run_id),
        )
        if row is None:
            raise HTTPException(404, "unknown run")
        cert = Path(row["pack_path"]) / "certificate.html"
        if not cert.is_file():
            from ..certificate import write_certificate

            write_certificate(row["pack_path"])
        return FileResponse(cert, media_type="text/html")

    @app.get("/v1/runs/{run_id}/meta")
    def run_meta(run_id: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> dict[str, Any]:
        from ..certificate import attribution
        from ..evidence import load_json

        row = ctl().store.one(
            "SELECT * FROM runs WHERE org_id=? AND run_id=?",
            (principal["org_id"], run_id),
        )
        if row is None:
            raise HTTPException(404, "unknown run")
        pack = Path(row["pack_path"])
        target = load_json(pack / "target.json") if (pack / "target.json").is_file() else {}
        verdict = load_json(pack / "verdict.json") if (pack / "verdict.json").is_file() else {}
        inner = target.get("target") or {}
        return {
            "run_id": row["run_id"],
            "manifest_sha256": row["manifest_sha256"],
            "created_at": row["created_at"],
            "driver": target.get("driver"),
            "variant": inner.get("variant"),
            "model": inner.get("model"),
            "started_at": target.get("started_at"),
            "attribution": attribution(verdict),
            "summary": verdict.get("summary") or {},
        }

    @app.get("/v1/runs/{run_id}/attestation")
    def run_attestation(run_id: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> JSONResponse:
        from ..attestation import ATTESTATION_NAME, write_attestation
        from ..evidence import load_json

        row = ctl().store.one(
            "SELECT * FROM runs WHERE org_id=? AND run_id=?",
            (principal["org_id"], run_id),
        )
        if row is None:
            raise HTTPException(404, "unknown run")
        path = Path(row["pack_path"]) / ATTESTATION_NAME
        if not path.is_file():
            write_attestation(row["pack_path"])
        return JSONResponse(load_json(path))

    @app.get("/v1/projects/{project_id}/baseline")
    def project_baseline_view(
        project_id: str, principal: dict[str, Any] = Depends(require("read-findings"))
    ) -> dict[str, Any]:
        from .baselines import project_baseline

        return project_baseline(ctl().store, principal["org_id"], project_id)

    @app.get("/v1/findings")
    def list_findings(
        project: str,
        status: str | None = None,
        principal: dict[str, Any] = Depends(require("read-findings")),
    ) -> dict[str, Any]:
        if status:
            rows = ctl().store.query(
                "SELECT * FROM findings WHERE org_id=? AND project_id=? AND status=? ORDER BY updated_at DESC",
                (principal["org_id"], project, status),
            )
        else:
            rows = ctl().store.query(
                "SELECT * FROM findings WHERE org_id=? AND project_id=? ORDER BY updated_at DESC",
                (principal["org_id"], project),
            )
        return {"findings": rows}

    @app.get("/v1/findings/{finding_id}")
    def get_finding(finding_id: str, principal: dict[str, Any] = Depends(require("read-findings"))) -> dict[str, Any]:
        row = ctl().store.one(
            "SELECT * FROM findings WHERE id=? AND org_id=?",
            (finding_id, principal["org_id"]),
        )
        if row is None:
            raise HTTPException(404, "unknown finding")
        events = ctl().store.query(
            "SELECT * FROM finding_events WHERE finding_id=? ORDER BY created_at",
            (finding_id,),
        )
        return {"finding": row, "events": events, "retest": retest_snippet(row)}

    @app.post("/v1/findings/{finding_id}/status")
    def finding_status(
        finding_id: str,
        status: str = Form(...),
        reason: str = Form(""),
        principal: dict[str, Any] = Depends(require("write-findings")),
    ) -> dict[str, Any]:
        try:
            return set_status(ctl().store, finding_id, principal["org_id"], status, principal["prefix"], reason)
        except KeyError:
            raise HTTPException(404, "unknown finding") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/v1/findings/{finding_id}/assign")
    def finding_assign(
        finding_id: str,
        assignee: str = Form(...),
        principal: dict[str, Any] = Depends(require("write-findings")),
    ) -> dict[str, Any]:
        try:
            return assign(ctl().store, finding_id, principal["org_id"], assignee, principal["prefix"])
        except KeyError:
            raise HTTPException(404, "unknown finding") from None

    @app.post("/v1/findings/{finding_id}/comment")
    def finding_comment(
        finding_id: str,
        text: str = Form(...),
        principal: dict[str, Any] = Depends(require("write-findings")),
    ) -> dict[str, Any]:
        try:
            return comment(ctl().store, finding_id, principal["org_id"], text, principal["prefix"])
        except KeyError:
            raise HTTPException(404, "unknown finding") from None

    @app.post("/v1/findings/{finding_id}/retest")
    def finding_retest(
        finding_id: str,
        principal: dict[str, Any] = Depends(require("write-findings")),
    ) -> dict[str, Any]:
        try:
            row = set_status(ctl().store, finding_id, principal["org_id"], "retesting", principal["prefix"])
        except KeyError:
            raise HTTPException(404, "unknown finding") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"finding": row, "command": retest_snippet(row)}

    @app.post("/v1/findings/{finding_id}/export")
    def finding_export(
        finding_id: str,
        destination: str = Form("github"),
        repo: str = Form(""),
        team_id: str = Form(""),
        principal: dict[str, Any] = Depends(require("write-findings")),
    ) -> dict[str, Any]:
        row = ctl().store.one(
            "SELECT * FROM findings WHERE id=? AND org_id=?",
            (finding_id, principal["org_id"]),
        )
        if row is None:
            raise HTTPException(404, "unknown finding")
        run = ctl().store.one(
            "SELECT manifest_sha256 FROM runs WHERE org_id=? AND run_id=?",
            (principal["org_id"], row["latest_run_id"]),
        )
        digest = (run or {}).get("manifest_sha256") or ""
        url = f"/findings/{finding_id}"
        if destination == "linear":
            result = export_linear(row, team_id=team_id, manifest_sha256=digest, url=url)
        else:
            result = export_github(row, repo=repo, manifest_sha256=digest, url=url)
        ctl().store.execute(
            "INSERT INTO audit (id, org_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            (
                "aud_" + secrets.token_hex(8),
                principal["org_id"],
                principal["prefix"],
                "finding.export",
                dumps({"finding_id": finding_id, "destination": destination, "dry_run": result.get("dry_run")}),
                now(),
            ),
        )
        return result

    @app.get("/v1/audit")
    def audit_log(principal: dict[str, Any] = Depends(require("admin"))) -> dict[str, Any]:
        rows = ctl().store.query(
            "SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT 200",
            (principal["org_id"],),
        )
        return {"events": rows}

    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        index = WEB_DIR / "index.html"
        if index.is_file():
            return HTMLResponse(index.read_text(encoding="utf-8"))
        return HTMLResponse("<p>New Chisel control plane. Missing apps/web/index.html.</p>")

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page() -> HTMLResponse:
        page = WEB_DIR / "verify.html"
        if page.is_file():
            return HTMLResponse(page.read_text(encoding="utf-8"))
        return HTMLResponse("<p>Verifier missing.</p>", status_code=404)

    @app.exception_handler(HTTPException)
    async def http_exc(_request: Request, exc: HTTPException) -> JSONResponse | PlainTextResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    return app


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
