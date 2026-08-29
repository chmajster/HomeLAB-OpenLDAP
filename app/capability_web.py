from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager
from app.ldap.capabilities import LDAPCapabilityProbeService
from app.models import PanelUser
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


@router.get("/ldap-capabilities", response_class=HTMLResponse)
def ldap_capabilities_page(
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    result = LDAPCapabilityProbeService(manager).inspect()
    return templates.TemplateResponse("ldap_capabilities.html", page_context(request, user, result=result, ldap=manager.settings))


@router.post("/ldap-capabilities/write-probe", response_class=HTMLResponse)
def ldap_capabilities_write_probe(
    request: Request,
    confirmation: str = Form(...),
    probe_base_dn: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    inspect = LDAPCapabilityProbeService(manager).inspect()
    if confirmation != "PROBE WRITE":
        return templates.TemplateResponse(
            "ldap_capabilities.html",
            page_context(request, user, result=inspect, ldap=manager.settings, error="Confirmation must equal PROBE WRITE."),
            status_code=409,
        )
    probe = LDAPCapabilityProbeService(manager).write_probe(probe_base_dn.strip() or None)
    AuditService(db).record(
        request_id=getattr(request.state, "request_id", "unknown"),
        panel_user=user.username,
        source_ip=request.client.host if request.client else None,
        operation="LDAP_WRITE_CAPABILITY_PROBE",
        status="SUCCESS" if probe["write_permissions"] == "allowed" else "PARTIAL",
        dn=probe["probe_base_dn"],
        new_value={
            "write_permissions": probe["write_permissions"],
            "cleanup_ok": probe["cleanup_ok"],
            "steps": [{"capability": step["capability"], "allowed": step["allowed"]} for step in probe["steps"]],
        },
    )
    return templates.TemplateResponse("ldap_capabilities.html", page_context(request, user, result=inspect, probe=probe, ldap=manager.settings))
