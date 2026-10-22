from aisec.evidence import IntegrityError, verify_manifest
from aisec.signing import generate_key, sign_pack, verify_signature
from test_evidence import build_store


def test_unsigned_pack_still_verifies_hashes(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    verify_manifest(store.root)
    assert not (store.root / "signature.json").exists()


def test_sign_and_verify_round_trip(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    key = generate_key()
    payload = sign_pack(store.root, key=key)
    assert payload["alg"] == "hmac-sha256"
    assert verify_signature(store.root, key=key)["signature"] == payload["signature"]
    verify_manifest(store.root)


def test_wrong_key_is_integrity_failure(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    sign_pack(store.root, key=generate_key())
    try:
        verify_signature(store.root, key=generate_key())
        raise AssertionError("expected IntegrityError")
    except IntegrityError:
        pass


def test_cli_sign_uses_env(tmp_path, monkeypatch):
    from aisec import cli

    store = build_store(tmp_path)
    store.seal()
    key = generate_key().hex()
    monkeypatch.setenv("AISEC_SIGNING_KEY", key)
    assert cli.main(["sign", str(store.root)]) == 0
    assert cli.main(["verify", str(store.root)]) == 0
