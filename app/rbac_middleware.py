from __future__ import annotations

import re

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.database import SessionLocal
from app.models import PanelUser
from app.rbac import user_allows
from app.session_store import active_session


RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/users/[^/]+/command-access(?:/delete)?$"), "ldap.sudo.write"),
    (re.compile(r"^/users/[^/]+/ssh-keys/(?:add|delete)$"), "ldap.ssh.write"),
    (re.compile(r"^/users/[^/]+/lifecycle$"), "ldap.lifecycle.write"),
    (re.compile(r"^/users/[^/]+/memberships$"), "ldap.users.write"),
    (re.compile(r"^/locked-accounts/unlock$"), "ldap.lifecycle.write"),
    (re.compile(r"^/ldif/import$"), "ldap.users.write"),
]


def _required_permission(path: str) -> str | None:
    for pattern, permission in RULES:
        if pattern.fullmatch(path):
            return permission
    return None


def enforce_web_rbac(request: Request) -> JSONResponse | None:
    """Protect form handlers that predate granular RBAC."""
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if request.url.path.startswith("/api/"):
        return None

    permission = _required_permission(request.url.path)
    legacy_bulk = request.url.path == "/bulk"
    if permission is None and not legacy_bulk:
        return None

    with SessionLocal() as db:
        session = active_session(request, db)
        if not session:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        user = db.get(PanelUser, session.user_id)
        if not user or not user.enabled:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        if legacy_bulk:
            if user.role not in {"Administrator", "Operator"}:
                return JSONResponse(status_code=403, content={"detail": "Bulk Operations remain restricted to Administrator and Operator roles"})
            return None
        if not user_allows(db, user, permission):
            return JSONResponse(status_code=403, content={"detail": f"Missing permission: {permission}"})
    return None


class RBACWebMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        denied = enforce_web_rbac(request)
        if denied is not None:
            return denied
        return await call_next(request)
