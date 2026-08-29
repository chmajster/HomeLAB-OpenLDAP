from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.browser import LDAPBrowserService
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager

router = APIRouter(prefix="/api/v1/browser", tags=["LDAP browser"])


@router.get("/node")
def browser_node(
    dn: str | None = Query(default=None, max_length=2048),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=500, ge=1, le=1000),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.read")),
) -> dict[str, Any]:
    return LDAPBrowserService(manager).node(dn, q=q, limit=limit)
