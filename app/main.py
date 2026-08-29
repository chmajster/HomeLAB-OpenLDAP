from __future__ import annotations

import logging
import re
import secrets
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.advanced_api import router as advanced_api_router
from app.api import router as api_router
from app.capability_api import router as capability_api_router
from app.capability_web import router as capability_web_router
from app.completion_web import router as completion_web_router
from app.config import get_settings
from app.database import init_db
from app.directory_web import router as directory_web_router
from app.ldap.connection import LDAPOperationError
from app.replication_api import router as replication_api_router
from app.security_api import router as security_api_router
from app.security_web import router as security_web_router
from app.server_api import router as server_api_router
from app.server_web import router as server_web_router
from app.tools_api import router as tools_api_router
from app.tools_web import router as tools_web_router
from app.web import router as web_router

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("homelab-openldap")

docs_url = "/docs" if settings.enable_docs or not settings.is_production else None
redoc_url = "/redoc" if settings.enable_docs or not settings.is_production else None
app = FastAPI(title=settings.app_name, version=settings.version, docs_url=docs_url, redoc_url=redoc_url)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, max_age=settings.session_max_age, same_site="lax", https_only=settings.session_https_only)
app.mount("/static", StaticFiles(directory="static"), name="static")

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def request_security_middleware(request: Request, call_next):
    supplied = request.headers.get("X-Request-ID", "")
    request_id = supplied if REQUEST_ID_RE.fullmatch(supplied) else "req_" + secrets.token_hex(12)
    request.state.request_id = request_id

    if request.url.path in {"/login", "/ldap-login"} and request.method.upper() == "POST":
        source = request.client.host if request.client else "unknown"
        now = time.monotonic()
        attempts = LOGIN_ATTEMPTS[source]
        while attempts and now - attempts[0] > 60:
            attempts.popleft()
        if len(attempts) >= 5:
            return JSONResponse(status_code=429, content={"error": "rate_limited", "message": "Too many login attempts. Try again later.", "request_id": request_id}, headers={"Retry-After": "60"})
        attempts.append(now)

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if settings.session_https_only:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(LDAPOperationError)
async def ldap_error_handler(request: Request, exc: LDAPOperationError):
    result = exc.result or {}
    logger.error("request_id=%s LDAP operation failed: %s result=%r", getattr(request.state, "request_id", "unknown"), exc, result)
    return JSONResponse(status_code=502, content={"error": "ldap_server_error", "message": str(exc), "ldap_result": result.get("result"), "ldap_description": result.get("description"), "ldap_message": result.get("message"), "request_id": getattr(request.state, "request_id", "unknown")})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.exception("request_id=%s Unhandled error", getattr(request.state, "request_id", "unknown"), exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "internal_error", "message": "Operacja nie powiodła się. Sprawdź log aplikacji używając Request ID.", "request_id": getattr(request.state, "request_id", "unknown")})


@app.on_event("startup")
def startup() -> None:
    init_db()


app.include_router(api_router)
app.include_router(tools_api_router)
app.include_router(advanced_api_router)
app.include_router(security_api_router)
app.include_router(server_api_router)
app.include_router(replication_api_router)
app.include_router(capability_api_router)
app.include_router(web_router)
app.include_router(directory_web_router)
app.include_router(tools_web_router)
app.include_router(completion_web_router)
app.include_router(security_web_router)
app.include_router(server_web_router)
app.include_router(capability_web_router)
