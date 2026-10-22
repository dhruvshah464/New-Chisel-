"""Redact secret-looking values before they are recorded or uploaded.

Used for argv in target.json, agent stderr, transcripts, tool arguments and
results, and anything copied into a sealed pack. Synthetic canaries (emails,
phone numbers planted in demo data) are left intact on purpose: they are the
evidence. Production tokens, passwords, PEM blocks and URL passwords are not.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "<redacted>"

SECRET_FLAG = re.compile(
    r"^--?[\w-]*(token|key|secret|passw|pwd|auth|credential)[\w-]*$", re.IGNORECASE
)
URL_CREDENTIALS = re.compile(r"(://[^/@:\s]+):[^/@\s]+@")
SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|passphrase|api[_-]?key|auth|credential|private[_-]?key|client[_-]?secret)$",
    re.IGNORECASE,
)
BEARER = re.compile(r"(?i)\b(bearer|token|api[_-]?key)\s+[A-Za-z0-9._\-/=+]{8,}")
ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|AUTHORIZATION)[A-Z0-9_]*)=([^\s]+)"
)
PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
KEY_SHAPED = re.compile(
    r"\b(sk-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9\-_]{16,}|ghp_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AIza[0-9A-Za-z\-_]{20,})\b"
)


def redact_args(args: list[str] | tuple[str, ...]) -> list[str]:
    """argv as it may be recorded: ``--token X``, ``--api-key=X`` and ``scheme://user:X@`` lose X."""
    out: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
        elif "=" in arg and SECRET_FLAG.match(arg.split("=", 1)[0]):
            out.append(arg.split("=", 1)[0] + "=" + REDACTED)
        elif SECRET_FLAG.match(arg):
            out.append(arg)
            redact_next = True
        else:
            out.append(redact_text(arg))
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    text = PEM.sub(REDACTED, text)
    text = URL_CREDENTIALS.sub(rf"\1:{REDACTED}@", text)
    text = BEARER.sub(lambda m: m.group(1) + " " + REDACTED, text)
    text = ASSIGNMENT.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    text = KEY_SHAPED.sub(REDACTED, text)
    return text


def redact_record(value: Any) -> Any:
    """Walk JSON-like structures; redact secret-looking keys and string leaves."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and SECRET_KEY.search(key):
                out[key] = REDACTED
            else:
                out[key] = redact_record(item)
        return out
    if isinstance(value, list):
        return [redact_record(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_record(item) for item in value)
    return value
