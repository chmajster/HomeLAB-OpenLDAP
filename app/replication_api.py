from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager
from app.ldap.replication import LDAPReplicationMonitorService

router = APIRouter(prefix="/api/v1/replication", tags=["Replication"])


@router.get("/status")
def replication_status(
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    rows = LDAPReplicationMonitorService(manager).status()
    summary = {
        "total": len(rows),
        "healthy": sum(1 for row in rows if row["status"] == "healthy"),
        "lagging": sum(1 for row in rows if row["status"] == "lagging"),
        "critical": sum(1 for row in rows if row["status"] == "critical"),
        "disconnected": sum(1 for row in rows if row["status"] == "disconnected"),
        "unknown": sum(1 for row in rows if row["status"] == "unknown"),
    }
    return {"summary": summary, "items": rows}
