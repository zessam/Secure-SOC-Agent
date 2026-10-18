"""Plain-code secret redaction applied to the ticket before it is stored (defence in depth)."""
from __future__ import annotations

import re

_PATTERNS = [
    # password: X / pwd=X / "password is X" / secret: X / api_key=X
    re.compile(r"(?i)\b(password|passwd|pwd|pass|secret|api[_-]?key|token)\b(\s*(?:is|:|=)\s*)([^\s,;|`'\"]{4,})"),
    # private keys / long bearer tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._\-]{20,}"),
]


def redact(text: str, known_secrets: list[str] | None = None) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    count = 0
    for secret in known_secrets or []:
        if secret and secret in text:
            count += text.count(secret)
            text = text.replace(secret, "[REDACTED]")
    for pat in _PATTERNS:
        if pat.groups >= 3:
            text, n = pat.subn(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text, n = pat.subn("[REDACTED]", text)
        count += n
    return text, count
