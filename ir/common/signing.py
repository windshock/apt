from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SignedRequest:
    """
    Minimal request signing for MVP.

    Canonical string:
      <timestamp>\n<method>\n<path>\n<body_sha256_hex>

    Headers:
      X-IR-Timestamp: unix epoch seconds
      X-IR-Signature: hex(HMAC-SHA256(key, canonical))
    """

    timestamp: int
    signature: str

    @staticmethod
    def sign(*, key: str, method: str, path: str, body: bytes, timestamp: int | None = None) -> "SignedRequest":
        ts = int(time.time()) if timestamp is None else int(timestamp)
        canonical = f"{ts}\n{method.upper()}\n{path}\n{sha256_hex(body)}"
        sig = hmac_sha256_hex(key, canonical)
        return SignedRequest(timestamp=ts, signature=sig)

    def verify(
        self,
        *,
        key: str,
        method: str,
        path: str,
        body: bytes,
        max_skew_seconds: int = 300,
        now: int | None = None,
    ) -> bool:
        n = int(time.time()) if now is None else int(now)
        if abs(n - int(self.timestamp)) > max_skew_seconds:
            return False
        canonical = f"{int(self.timestamp)}\n{method.upper()}\n{path}\n{sha256_hex(body)}"
        expected = hmac_sha256_hex(key, canonical)
        return hmac.compare_digest(expected, self.signature)

