from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.database import get_db
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager
from app.ldap.capabilities import LDAPCapabilityProbeService

router = APIRouter(prefix="/api/v1/ldap/capabilities", tags=["LDAP capabilities"])


class WriteProbePayload(BaseModel):
    confirm: bool = False
    probe_base_dn: str | None = None


@router.get("")
def inspect_capabilities(
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    return LDAPCapabilityProbeService(manager).inspect()


@router.post("/write-probe")
def run_write_probe(
    payload: WriteProbePayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(status_code=409, detail="Write probe requires confirm=true")
    result = LDAPCapabilityProbeService(manager).write_probe(payload.probe_base_dn)
    AuditService(db).record(
        request_id=getattr(request.state, "request_id", "unknown"),
        panel_user=auth.username,
        source_ip=request.client.host if request.client else None,
        operation="LDAP_WRITE_CAPABILITY_PROBE",
        status="SUCCESS" if result["write_permissions"] == "allowed" else "PARTIAL",
        dn=result["probe_base_dn"],
        new_value={
            "write_permissions": result["write_permissions"],
            "cleanup_ok": result["cleanup_ok"],
            "steps": [{"capability": step["capability"], "allowed": step["allowed"]} for step in result["steps"]],
        },
    )
    return result
