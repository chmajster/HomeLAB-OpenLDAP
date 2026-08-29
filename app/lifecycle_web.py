from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager
from app.ldap.access import LDAPAccountLifecycleService
from app.lifecycle_manager import LDAPLifecycleManagerService
from app.rbac import user_allows
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()


def require_lifecycle(request: Request, db: Session, permission: str):
    user = require_web_user(request, db)
    if not user_allows(db, user, permission):
        raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
    return user


@router.get("/lifecycle", response_class=HTMLResponse)
def lifecycle_page(
    request: Request,
    state: str = "all",
    search: str = "",
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_lifecycle(request, db, "ldap.lifecycle.read")
    report = LDAPLifecycleManagerService(manager).report(state=state, search=search)
    return templates.TemplateResponse(
        "lifecycle.html",
        page_context(request, user, report=report, state=state, search=search),
    )


@router.post("/lifecycle/{username}")
def lifecycle_action(
    username: str,
    request: Request,
    action: str = Form(...),
    expires_on: str = Form(""),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_lifecycle(request, db, "ldap.lifecycle.write")
    verify_csrf(request, csrf_token)
    if confirmation != "APPLY":
        raise HTTPException(status_code=409, detail="Confirmation must equal APPLY")
    service = LDAPAccountLifecycleService(manager, settings.uid_min, settings.uid_max)
    if action == "enable":
        result = service.set_enabled(username, True)
    elif action == "disable":
        result = service.set_enabled(username, False)
    elif action == "clear_expiry":
        result = service.set_expiry(username, None)
    elif action == "set_expiry":
        try:
            expiry = date.fromisoformat(expires_on)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Expiry date must use YYYY-MM-DD") from exc
        result = service.set_expiry(username, expiry)
    elif action == "require_password_change":
        result = service.require_password_change(username, True)
    elif action == "clear_password_change":
        result = service.require_password_change(username, False)
    else:
        raise HTTPException(status_code=422, detail="Unsupported lifecycle action")
    AuditService(db).record(
        request_id=getattr(request.state, "request_id", "unknown"),
        panel_user=user.username,
        source_ip=request.client.host if request.client else None,
        operation="ACCOUNT_LIFECYCLE_UPDATE",
        status="SUCCESS",
        dn=result["dn"],
        new_value={"action": action, "expires_on": expires_on or None},
    )
    return RedirectResponse("/lifecycle", status_code=303)
