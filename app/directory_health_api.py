from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.directory_health import LDAPDirectoryHealthService
from app.ldap import LDAPConnectionManager

router = APIRouter(prefix="/api/v1/directory-health", tags=["Directory health"])


@router.get("")
def directory_health(
    limit: int = Query(default=5000, ge=1, le=5000),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.read")),
) -> dict[str, Any]:
    return LDAPDirectoryHealthService(manager).scan(limit=limit)
