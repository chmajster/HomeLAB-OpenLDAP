from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager
from app.lifecycle_manager import LDAPLifecycleManagerService

router = APIRouter(prefix="/api/v1/lifecycle", tags=["Lifecycle"])


@router.get("/accounts")
def lifecycle_accounts(
    state: str | None = Query(default=None, pattern=r"^(all|active|expiring|expired|locked)$"),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=1000, ge=1, le=5000),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.lifecycle.read")),
) -> dict[str, Any]:
    return LDAPLifecycleManagerService(manager).report(state=state, search=search, limit=limit)
