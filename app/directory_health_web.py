from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_ldap_manager
from app.directory_health import LDAPDirectoryHealthService
from app.ldap import LDAPConnectionManager
from app.rbac import user_allows
from app.web import page_context, require_web_user

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/directory-health", response_class=HTMLResponse)
def directory_health_page(
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_web_user(request, db)
    if not user_allows(db, user, "ldap.read"):
        raise HTTPException(status_code=403, detail="Missing permission: ldap.read")
    report = LDAPDirectoryHealthService(manager).scan()
    return templates.TemplateResponse("directory_health.html", page_context(request, user, report=report))
