"""FastAPI server used by the browser extension.

Run with:  python -m api            (listens on http://127.0.0.1:8600)
Token:     python -m api token      (prints the token to paste into the extension)
"""

from __future__ import annotations

import hmac
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from tia import config
from tia.keys import KEY_FIELDS
from tia.storage import Store

from .lookup import LookupService


class VerdictIn(BaseModel):
    target: str
    verdict: Optional[str] = None  # "malicious", "benign", or null to clear
    note: str = ""


def create_app(service: LookupService | None = None) -> FastAPI:
    svc = service or LookupService(Store(config.db_path()))
    app = FastAPI(title=f"{config.APP_NAME} API", version=config.APP_VERSION,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.state.service = svc
    # Only browser extensions may call this from a browser context.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^(chrome|moz|safari-web)-extension://.*$",
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "X-TI-Token", "Content-Type"],
    )

    def require_token(authorization: Optional[str] = Header(None), x_ti_token: Optional[str] = Header(None)):
        sent = x_ti_token or ""
        if not sent and authorization and authorization.lower().startswith("bearer "):
            sent = authorization[7:]
        expected = svc.token()
        if not expected or not hmac.compare_digest(sent.strip(), expected):
            raise HTTPException(status_code=401, detail="Missing or invalid API token.")

    @app.get("/api/health")
    def health():
        keys = svc.keys()
        return {
            "ok": True,
            "app": config.APP_NAME,
            "version": config.APP_VERSION,
            "sources": {**{KEY_FIELDS[k][0]: bool(v) for k, v in keys.items()}, "RDAP": True},
            "queue": svc.queue_size(),
            "min_interval_seconds": svc.min_interval(),
        }

    @app.get("/api/lookup", dependencies=[Depends(require_token)])
    def lookup(target: str = Query(..., description="URL or host name"), force: bool = False):
        return svc.lookup(target, force=force)

    @app.post("/api/verdict", dependencies=[Depends(require_token)])
    def verdict(body: VerdictIn):
        if body.verdict not in (None, "", "malicious", "benign"):
            raise HTTPException(status_code=422, detail="verdict must be 'malicious', 'benign' or null")
        return svc.set_verdict(body.target, body.verdict or None, body.note, username="browser extension")

    @app.get("/api/auth-check", dependencies=[Depends(require_token)])
    def auth_check():
        return {"ok": True}

    return app
