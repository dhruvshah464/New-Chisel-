import io
import tarfile

import pytest

from aisec.cloud.app import create_app
from aisec.cloud.upload import tar_pack
from aisec.signing import generate_key, sign_pack
from conftest import SCENARIOS_DIR

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def key():
    return generate_key()


@pytest.fixture
def client(tmp_path, key):
    app = create_app(data_dir=tmp_path / "control", signing_key=key)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def org(client):
    response = client.post("/v1/bootstrap")
    assert response.status_code == 200, response.text
    body = response.json()
    return body


def auth(org):
    return {"Authorization": "Bearer " + org["token"]}


def test_health_and_security_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in response.headers


def test_desk_is_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Independent evidence" in page.text
    css = client.get("/static/style.css")
    assert css.status_code == 200 and "Iowan Old Style" in css.text
    verify = client.get("/verify")
    assert verify.status_code == 200 and "Hash the pack yourself" in verify.text


def test_bootstrap_once(client, org):
    again = client.post("/v1/bootstrap")
    assert again.status_code == 409


def test_local_unlock_opens_the_desk(client, org):
    response = client.post("/v1/local-unlock")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["token"].startswith("aisec_")
    me = client.get("/v1/me", headers={"Authorization": "Bearer " + body["token"]})
    assert me.status_code == 200


def test_upload_opens_finding_tickets(client, org, key, tmp_path):
    from aisec import cli

    runs = tmp_path / "runs"
    assert (
        cli.main(
            [
                "run",
                "--variant",
                "vulnerable",
                "--replay-only",
                "--scenarios",
                str(SCENARIOS_DIR),
                "--runs-root",
                str(runs),
            ]
        )
        == 1
    )
    run_dir = next(p for p in runs.iterdir() if p.is_dir())
    sign_pack(run_dir, key=key)
    blob = tar_pack(run_dir)
    response = client.post(
        "/v1/runs",
        data={"project": org["project_id"]},
        files={"pack": ("pack.tar.gz", io.BytesIO(blob), "application/gzip")},
        headers=auth(org),
    )
    assert response.status_code == 200, response.text
    uploaded = response.json()
    assert uploaded["findings_opened"] >= 6
    inbox = client.get("/v1/findings", params={"project": org["project_id"]}, headers=auth(org))
    assert inbox.status_code == 200
    findings = inbox.json()["findings"]
    assert {f["status"] for f in findings} == {"open"}
    first = findings[0]
    changed = client.post(
        f"/v1/findings/{first['id']}/status",
        data={"status": "in_progress"},
        headers=auth(org),
    )
    assert changed.status_code == 200 and changed.json()["status"] == "in_progress"
    assigned = client.post(
        f"/v1/findings/{first['id']}/assign",
        data={"assignee": "ada"},
        headers=auth(org),
    )
    assert assigned.json()["assignee"] == "ada"
    retest = client.post(f"/v1/findings/{first['id']}/retest", headers=auth(org))
    assert retest.status_code == 200 and "aisec run" in retest.json()["command"]
    exported = client.post(
        f"/v1/findings/{first['id']}/export",
        data={"destination": "github", "repo": "acme/agent"},
        headers=auth(org),
    )
    assert exported.status_code == 200 and exported.json()["dry_run"] is True
    report = client.get(f"/v1/runs/{uploaded['run_id']}/report", headers=auth(org))
    assert report.status_code == 200 and "html" in report.headers["content-type"]
    attest = client.get(f"/v1/runs/{uploaded['run_id']}/attestation", headers=auth(org))
    assert attest.status_code == 200, attest.text
    body = attest.json()
    assert body["type"] == "new-chisel.attestation.v1"
    assert body["not_a_certification"] is True
    assert "1420 Larkspur" not in attest.text
    meta = client.get(f"/v1/runs/{uploaded['run_id']}/meta", headers=auth(org))
    assert meta.status_code == 200
    assert meta.json()["attribution"]["failed"] >= 1
    audit = client.get("/v1/audit", headers=auth(org))
    assert any(e["action"] == "pack.upload" for e in audit.json()["events"])


def test_public_verify_hash_checks_without_storing(client, tmp_path):
    from test_evidence import build_store

    store = build_store(tmp_path)
    store.write_text("report.html", "<html></html>\n")
    store.write_text("report.sarif", "{}\n")
    store.write_text("junit.xml", "<testsuite/>\n")
    store.seal()
    blob = tar_pack(store.root)
    response = client.post(
        "/v1/public/verify",
        files={"pack": ("pack.tar.gz", io.BytesIO(blob), "application/gzip")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["signed"] is False
    assert "not issued by a model vendor" in body["issuer"]
    listed = client.get("/v1/runs", params={"project": "none"})
    assert listed.status_code == 401


def test_unsigned_pack_is_refused(client, org, tmp_path):
    from test_evidence import build_store

    store = build_store(tmp_path)
    store.write_text("report.html", "<html></html>\n")
    store.write_text("report.sarif", "{}\n")
    store.write_text("junit.xml", "<testsuite/>\n")
    store.seal()
    blob = tar_pack(store.root)
    response = client.post(
        "/v1/runs",
        data={"project": org["project_id"]},
        files={"pack": ("pack.tar.gz", io.BytesIO(blob), "application/gzip")},
        headers=auth(org),
    )
    assert response.status_code == 400
    assert "unsigned" in response.json()["error"]


def test_path_traversal_tarball_is_refused(client, org, tmp_path):
    from aisec.cloud.ingest import extract_tar
    from aisec.cloud.security import IngestRefused

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="../evil.txt")
        data = b"nope"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    try:
        extract_tar(buf.getvalue(), tmp_path / "dest")
        raise AssertionError("expected IngestRefused")
    except IngestRefused:
        pass
