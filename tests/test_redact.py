from aisec.redact import REDACTED, redact_args, redact_record, redact_text


def test_redact_args_strips_flag_values_and_url_passwords():
    assert redact_args(
        ["curl", "https://user:s3cret@example.com/x", "--token", "abc", "--api-key=xyz"]
    ) == ["curl", f"https://user:{REDACTED}@example.com/x", "--token", REDACTED, f"--api-key={REDACTED}"]


def test_redact_text_strips_key_shaped_secrets_and_pem():
    text = "export ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz\n-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
    out = redact_text(text)
    assert "sk-ant-" not in out
    assert "BEGIN PRIVATE KEY" not in out
    assert REDACTED in out


def test_redact_record_redacts_secret_keys_but_keeps_canaries():
    record = {
        "agent_stderr_tail": "Authorization: Bearer sk-ant-abcdefghijklmnopqrstuvwxyz boom",
        "api_key": "should-go",
        "arguments": {"to": "ana.souza@example.com", "token": "ghp_abcdefghijklmnopqrstuv"},
    }
    out = redact_record(record)
    assert out["api_key"] == REDACTED
    assert out["arguments"]["to"] == "ana.souza@example.com"
    assert REDACTED in out["agent_stderr_tail"]
    assert "sk-ant-" not in out["agent_stderr_tail"]
