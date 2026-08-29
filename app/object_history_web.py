from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.object_history import ObjectHistoryService
from app.rbac import user_allows
from app.web import page_context, require_web_user

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/history", response_class=HTMLResponse)
def history_page(
    request: Request,
    dn: str,
    operation: str = "",
    status: str = "",
    limit: int = 200,
    db: Session = Depends(get_db),
):
    user = require_web_user(request, db)
    if not user_allows(db, user, "audit.read"):
        raise HTTPException(status_code=403, detail="Missing permission: audit.read")
    report = ObjectHistoryService(db).timeline(
        dn,
        operation=operation.strip() or None,
        status=status.strip() or None,
        limit=min(max(limit, 1), 500),
    )
    return templates.TemplateResponse(
        "object_history.html",
        page_context(request, user, report=report, operation=operation, status=status, limit=limit),
    )
