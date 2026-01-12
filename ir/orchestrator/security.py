from __future__ import annotations

import secrets

from fastapi import HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ir.common.signing import SignedRequest
from ir.orchestrator.config import Settings


_basic = HTTPBasic(auto_error=False)


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


def require_ui_auth(credentials: HTTPBasicCredentials | None, settings: Settings) -> str:
    """
    UI auth (browser-friendly):
    - HTTP Basic with IR_UI_USER / IR_UI_PASSWORD
    - Can be disabled via IR_UI_ENABLED=0
    """
    if not settings.ui_enabled:
        raise HTTPException(status_code=404, detail="ui disabled")
    if credentials is None:
        raise HTTPException(status_code=401, detail="ui auth required", headers={"WWW-Authenticate": "Basic"})
    ok_user = secrets.compare_digest(credentials.username or "", settings.ui_user or "")
    ok_pass = secrets.compare_digest(credentials.password or "", settings.ui_password or "")
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="ui unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def ui_basic_dep():
    """
    Small helper so we can inject HTTPBasic into app.py without importing the security object there.
    """
    return _basic

