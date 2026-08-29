from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import AuthContext, require_permission
from app.object_history import ObjectHistoryService

router = APIRouter(prefix="/api/v1/history", tags=["Object history"])


@router.get("")
def object_history(
    dn: str = Query(min_length=1, max_length=2048),
    operation: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("audit.read")),
) -> dict[str, Any]:
    return ObjectHistoryService(db).timeline(dn, operation=operation, status=status, limit=limit)
