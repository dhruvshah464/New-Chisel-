"""Contracts from the world-scale notary plan: inspect, verify --json, badge, HTTP proxy."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aisec import cli
from aisec.badge import render_badge
from aisec.evidence import inspect
from aisec.proxy import _claim_port, _contains_exc, http_security_settings, record_would_leak
from aisec.signing import generate_key, sign_pack
from test_evidence import build_store
from test_unique_product import _attack, _pack

FIXTURE = Path(__file__).parent / "fixtures" / "fixture_server.py"
VERIFY_HTML = Path(__file__).resolve().parents[1] / "site/verify.html"
SAMPLE_INDEX = Path(__file__).resolve().parents[1] / "site/sample/index.html"
CI_YML = Path(__file__).resolve().parent / os.path.join("..", ".github", "workflows", "ci.yml")


def make_writable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IWUSR)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_port(port: int, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listening on 127.0.0.1:{port}")


def test_inspect_unsigned_pack_is_ok(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    report = inspect(store.root)
    assert report["ok"] is True
    assert report["error"] is None
    assert report["missing"] == report["changed"] == report["extra"] == []
    assert report["manifest_sha256"] and len(report["manifest_sha256"]) == 64
    assert report["sealed_at"]


def test_verify_json_hashes_pass_unsigned(tmp_path, capsys):
    store = build_store(tmp_path)
    store.seal()
    assert cli.main(["verify", "--json", str(store.root)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["signature"] is None
    assert "OK " not in captured.out


def test_verify_json_hash_mismatch_exit_3(tmp_path, capsys):
    store = build_store(tmp_path)
    store.seal()
    verdict = store.root / "verdict.json"
    make_writable(verdict)
    verdict.write_text(verdict.read_text().replace("FAILED", "RESISTED"))
    assert cli.main(["verify", "--json", str(store.root)]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "verdict.json" in payload["changed"]


def test_verify_json_hmac_fail_does_not_flip_ok(tmp_path, capsys, monkeypatch):
    store = build_store(tmp_path)
    store.seal()
    key = generate_key()
    monkeypatch.setenv("AISEC_SIGNING_KEY", key.hex())
    sign_pack(store.root, key=key)
    sig_path = store.root / "signature.json"
    make_writable(sig_path)
    payload = json.loads(sig_path.read_text())
    payload["signature"] = "00" * 32
    sig_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli.main(["verify", str(store.root)]) == 3
    capsys.readouterr()
    assert cli.main(["verify", "--json", str(store.root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["signature"]["ok"] is False
    assert report["signature"]["error"] == "hmac_mismatch"


def test_verify_json_signed_without_key(tmp_path, capsys, monkeypatch):
    store = build_store(tmp_path)
    store.seal()
    sign_pack(store.root, key=generate_key())
    monkeypatch.delenv("AISEC_SIGNING_KEY", raising=False)
    monkeypatch.delenv("AISEC_SIGNING_KEY_FILE", raising=False)
    assert cli.main(["verify", "--json", str(store.root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["signature"]["ok"] is False
    assert report["signature"]["error"] == "key_missing"


@pytest.mark.parametrize(
    "mutate,error",
    [
        ("alg", "alg_unsupported"),
        ("key_id", "key_id_mismatch"),
        ("digest", "manifest_digest_mismatch"),
    ],
)
def test_verify_json_hmac_overlay_errors_do_not_flip_ok(tmp_path, capsys, monkeypatch, mutate, error):
    # Value: protects=verify --json keeps hashes ok when nested HMAC reports alg_unsupported, key_id_mismatch, or manifest_digest_mismatch; fails_when=those overlay errors are dropped, inverted, or flip top-level ok; why_new=existing tests cover hmac_mismatch and key_missing only; seam=none; no_claim=does not prove verify_signature raise paths for the same mutations
    store = build_store(tmp_path)
    store.seal()
    key = generate_key()
    monkeypatch.setenv("AISEC_SIGNING_KEY", key.hex())
    sign_pack(store.root, key=key)
    sig_path = store.root / "signature.json"
    make_writable(sig_path)
    payload = json.loads(sig_path.read_text(encoding="utf-8"))
    if mutate == "alg":
        payload["alg"] = "none"
    elif mutate == "key_id":
        payload["key_id"] = "sha256:" + ("ab" * 32)
    else:
        payload["manifest_sha256"] = "00" * 32
    sig_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli.main(["verify", "--json", str(store.root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["signature"]["ok"] is False
    assert report["signature"]["error"] == error


@pytest.mark.parametrize(
    "kind,error",
    [
        ("missing", "missing_manifest"),
        ("invalid", "invalid_manifest"),
        ("unsealed", "unsealed"),
        ("files", "invalid_manifest"),
    ],
)
def test_verify_json_integrity_errors(tmp_path, capsys, kind, error):
    # Value: protects=verify --json reports missing_manifest, invalid_manifest (including a files map with no sha256), and unsealed without raising; fails_when=inspect drops the files-map guard or maps those states to ok; why_new=the table covered JSON/missing/unsealed but not a sealed manifest whose files entries lack sha256; seam=none; no_claim=does not prove verify_manifest raise text for the same bytes
    store = build_store(tmp_path)
    if kind == "missing":
        target = tmp_path / "empty"
        target.mkdir()
        run = str(target)
    elif kind == "invalid":
        store.seal()
        manifest = store.root / "manifest.json"
        make_writable(manifest)
        manifest.write_text("{not json", encoding="utf-8")
        run = str(store.root)
    elif kind == "files":
        store.seal()
        manifest = store.root / "manifest.json"
        make_writable(manifest)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"]["verdict.json"] = {"bytes": 12}
        manifest.write_text(json.dumps(data) + "\n", encoding="utf-8")
        run = str(store.root)
    else:
        (store.root / "manifest.json").write_text('{"sealed": false, "files": {}}\n', encoding="utf-8")
        run = str(store.root)
    assert cli.main(["verify", "--json", run]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["error"] == error


def test_verify_usage_is_exit_2_without_json(capsys):
    assert cli.main(["verify", "no-such-run"]) == 2
    assert "{" not in capsys.readouterr().out


def test_human_verify_unchanged_on_good_pack(tmp_path, capsys):
    store = build_store(tmp_path)
    store.seal()
    assert cli.main(["verify", str(store.root)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK ")
    assert "manifest sha256 " in out


def test_badge_href_is_verify_html(tmp_path):
    run_dir = _pack(tmp_path, "badge-href", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    svg = render_badge(run_dir)
    assert 'href="verify.html"' in svg


def test_ci_yml_checks_sample_packs():
    text = CI_YML.read_text(encoding="utf-8")
    assert "aisec spec --check site/sample/fixed" in text
    assert "aisec verify --json site/sample/fixed" in text
    assert "aisec spec --check site/sample/vulnerable" in text
    assert "aisec verify --json site/sample/vulnerable" in text


def test_verify_html_uses_relative_samples_and_live_region():
    text = VERIFY_HTML.read_text(encoding="utf-8")
    assert "sample/fixed/manifest.json" in text or 'loadSample("fixed")' in text
    assert "sample/fixed/" in text
    assert 'href="/sample' not in text
    assert "aria-live" in text and "aria-atomic" in text
    assert "HASHES MATCH" in text
    assert "Could not load the sample. Try again." in text
    assert "webkitdirectory" in text
    assert "Load fixed sample" in text
    assert SAMPLE_INDEX.is_file()
    sample = SAMPLE_INDEX.read_text(encoding="utf-8")
    assert 'class="sample"' in sample and 'class="pill' in sample


def test_sample_packs_verify_json():
    root = Path(__file__).resolve().parents[1]
    for name in ("fixed", "vulnerable"):
        assert cli.main(["verify", "--json", str(root / "site" / "sample" / name)]) == 0
        assert cli.main(["spec", "--check", str(root / "site" / "sample" / name)]) == 0


def test_transport_sse_is_rejected(capsys):
    assert cli.main(["proxy", "--transport", "sse", "--port", "9", "--events", "x", "--", "true"]) == 2
    assert "use --transport http" in capsys.readouterr().err


def test_non_loopback_refused(capsys, tmp_path):
    events = tmp_path / "runs" / "nl"
    assert (
        cli.main(
            [
                "proxy",
                "--transport",
                "http",
                "--host",
                "0.0.0.0",
                "--port",
                "9",
                "--events",
                str(events),
                "--",
                "true",
            ]
        )
        == 2
    )
    assert "AISEC_NON_LOOPBACK" in capsys.readouterr().err
    assert not events.exists()


def test_allow_non_loopback_warns_and_does_not_refuse(tmp_path, capsys):
    # Value: protects=--allow-non-loopback on a non-loopback host prints the customer-host warning and does not emit AISEC_NON_LOOPBACK; fails_when=the warning is dropped or the refuse check ignores the flag; why_new=test_non_loopback_refused covers refuse only; seam=none; no_claim=does not prove the bound address is the customer's
    events = tmp_path / "runs" / "nl-ok"
    code = cli.main(
        [
            "proxy",
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            str(free_port()),
            "--events",
            str(events),
            "--allow-non-loopback",
            "--timeout",
            "0.3",
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(1)",
        ]
    )
    err = capsys.readouterr().err
    assert "AISEC_NON_LOOPBACK" not in err
    assert "does not prove the host is the customer's" in err
    assert code == 2


def test_existing_events_dir_refused(tmp_path, capsys):
    events = tmp_path / "runs" / "exists"
    events.mkdir(parents=True)
    assert (
        cli.main(
            [
                "proxy",
                "--transport",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--events",
                str(events),
                "--",
                "true",
            ]
        )
        == 2
    )
    assert "AISEC_EVENTS_EXISTS" in capsys.readouterr().err


def test_record_would_leak_named_key_and_env(monkeypatch):
    # Value: protects=record_would_leak is true for a named secret key, an env secret substring, or a URL query key such as api_key; fails_when=_query_has_secret or named/env checks are removed or inverted; why_new=the test covered named keys and env values but not query-string secret keys; seam=none; no_claim=does not prove LeakSafeInterceptor os._exit on a live HTTP call
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-planted-leak-test-key")
    assert record_would_leak({"kind": "call", "arguments": {"api_key": "x"}})
    assert record_would_leak({"kind": "call", "arguments": {"text": "sk-planted-leak-test-key"}})
    assert record_would_leak({"kind": "call", "arguments": {"url": "https://example.test/x?api_key=planted"}})
    assert not record_would_leak({"kind": "call", "arguments": {"url": "https://example.test/x?q=hello"}})
    assert not record_would_leak({"kind": "call", "arguments": {"text": "hello"}, "tool": "echo"})


@pytest.mark.asyncio
async def test_forbidden_origin_is_403():
    from mcp.server.transport_security import TransportSecurityMiddleware
    from starlette.requests import Request

    middleware = TransportSecurityMiddleware(http_security_settings())

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    def request(origin: str | None) -> Request:
        headers = [(b"host", b"127.0.0.1:9")]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        return Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/mcp",
                "raw_path": b"/mcp",
                "query_string": b"",
                "headers": headers,
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 9),
            },
            receive,
        )

    forbidden = await middleware.validate_request(request("https://evil.example"), is_post=False)
    assert forbidden is not None and forbidden.status_code == 403
    assert await middleware.validate_request(request(None), is_post=False) is None
    loopback = await middleware.validate_request(request("http://127.0.0.1:9"), is_post=False)
    assert loopback is None


def test_http_proxy_records_seal_and_verify(tmp_path):
    # Value: protects=HTTP proxy seal writes proxy_http target.tools from events.jsonl and an INCONCLUSIVE proxy_capture_only verdict that verify --json accepts; fails_when=_tools_from_events drops list/call names or seal skips target.json; why_new=the test already sealed and verified but never asserted target.tools; seam=none; no_claim=does not prove reseal leaves a pre-written target.json untouched
    port = free_port()
    run_dir = tmp_path / "runs" / "http-1"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aisec.cli",
            "proxy",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--events",
            str(run_dir),
            "--",
            sys.executable,
            str(FIXTURE),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_port(port)
        _run_echo(f"http://127.0.0.1:{port}/mcp")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
    assert run_dir.is_dir()
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "echo" in events
    assert cli.main(["proxy", "seal", str(run_dir)]) == 0
    assert cli.main(["verify", "--json", str(run_dir)]) == 0
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["reason"] == "proxy_capture_only"
    target = json.loads((run_dir / "target.json").read_text(encoding="utf-8"))
    assert target["driver"] == "proxy_http"
    assert "echo" in target["tools"]


def test_http_proxy_key_leak_aborts_without_writing_secret(tmp_path, monkeypatch):
    port = free_port()
    run_dir = tmp_path / "runs" / "leak-1"
    env = os.environ.copy()
    env["ANTHROPIC_API_KEY"] = "sk-planted-leak-test-key"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aisec.cli",
            "proxy",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--events",
            str(run_dir),
            "--",
            sys.executable,
            str(FIXTURE),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        wait_for_port(port)
        try:
            _run_echo(f"http://127.0.0.1:{port}/mcp", text="sk-planted-leak-test-key")
        except Exception:
            pass
        try:
            _, err = proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate(timeout=4)
        assert proc.returncode == 2
        assert "AISEC_KEY_LEAK" in (err or "")
    finally:
        if proc.poll() is None:
            proc.kill()
    blob = ""
    if run_dir.is_dir():
        for path in run_dir.rglob("*"):
            if path.is_file():
                blob += path.read_text(encoding="utf-8", errors="ignore")
    assert "sk-planted-leak-test-key" not in blob


def test_http_proxy_timeout(tmp_path, capsys):
    events = tmp_path / "runs" / "to"
    code = cli.main(
        [
            "proxy",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(free_port()),
            "--events",
            str(events),
            "--timeout",
            "0.2",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ]
    )
    assert code == 2
    assert "AISEC_TIMEOUT" in capsys.readouterr().err


def test_http_proxy_session_drop(tmp_path, capsys):
    events = tmp_path / "runs" / "drop"
    code = cli.main(
        [
            "proxy",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(free_port()),
            "--events",
            str(events),
            "--timeout",
            "3",
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(1)",
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "AISEC_SESSION_DROP" in err or "AISEC_TIMEOUT" in err


def test_contains_exc_walks_nested_exception_group():
    # Value: protects=HTTP proxy classifies TimeoutError inside a nested ExceptionGroup so session timeout still prints AISEC_TIMEOUT; fails_when=_contains_exc stops at the group and skips inners; why_new=timeout tests raise TimeoutError at the top, not nested in ExceptionGroup; seam=none; no_claim=does not prove uvicorn or anyio wrap a given failure in ExceptionGroup
    inner = ExceptionGroup("inner", [OSError("x"), TimeoutError("t")])
    grouped = ExceptionGroup("outer", [ValueError("v"), inner])
    assert _contains_exc(grouped, (TimeoutError,))
    assert not _contains_exc(grouped, (KeyError,))
    assert not _contains_exc(ValueError("v"), (TimeoutError,))


def test_claim_port_stays_listening():
    port = free_port()
    sock = _claim_port("127.0.0.1", port)
    try:
        assert sock.fileno() >= 0
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            pass
    finally:
        sock.close()


def test_http_proxy_session_timeout_after_initialize(tmp_path):
    port = free_port()
    run_dir = tmp_path / "runs" / "session-to"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aisec.cli",
            "proxy",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--events",
            str(run_dir),
            "--timeout",
            "0.8",
            "--",
            sys.executable,
            str(FIXTURE),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_port(port)
        try:
            _run_echo(f"http://127.0.0.1:{port}/mcp")
        except Exception:
            pass
        _, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate(timeout=4)
        raise
    assert proc.returncode == 2
    assert "AISEC_TIMEOUT" in (err or "")


def test_http_proxy_eaddrinuse(tmp_path, capsys):
    port = free_port()
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    blocker.bind(("127.0.0.1", port))
    blocker.listen(1)
    try:
        events = tmp_path / "runs" / "inuse"
        code = cli.main(
            [
                "proxy",
                "--transport",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--events",
                str(events),
                "--",
                sys.executable,
                str(FIXTURE),
            ]
        )
        assert code == 2
        assert "AISEC_EADDRINUSE" in capsys.readouterr().err
    finally:
        blocker.close()


def test_proxy_wrap_path_still_requires_events(capsys):
    code = cli.main(["proxy", "--server-name", "fixture", "--", sys.executable, str(FIXTURE)])
    assert code == 2
    assert "AISEC_EVENTS" in capsys.readouterr().err


def _run_echo(url: str, text: str = "hello") -> None:
    import asyncio

    asyncio.run(_echo(url, text))


async def _echo(url: str, text: str) -> None:
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("echo", {"text": text})
            assert result.content
