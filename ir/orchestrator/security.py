from __future__ import annotations

from fastapi import HTTPException, Request

from ir.common.signing import SignedRequest
from ir.orchestrator.config import Settings


async def require_auth(request: Request, settings: Settings) -> str:
    """
    MVP auth:
    - Always require X-IR-Key == IR_SHARED_KEY
    - Optionally require signature (IR_REQUIRE_SIGNATURE=1)
    """

    key = request.headers.get("X-IR-Key")
    if not key or key != settings.shared_key:
        raise HTTPException(status_code=401, detail="unauthorized")

    if settings.require_signature:
        ts = request.headers.get("X-IR-Timestamp")
        sig = request.headers.get("X-IR-Signature")
        if not ts or not sig:
            raise HTTPException(status_code=401, detail="missing signature")
        body = await request.body()
        signed = SignedRequest(timestamp=int(ts), signature=sig)
        ok = signed.verify(
            key=settings.shared_key,
            method=request.method,
            path=request.url.path,
            body=body,
        )
        if not ok:
            raise HTTPException(status_code=401, detail="bad signature")

    return key

