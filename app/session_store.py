from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PanelSession, PanelUser
from app.security import generate_csrf_token


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def establish_session(request: Request, db: Session, user: PanelUser, max_age: int) -> PanelSession:
    raw_token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    row = PanelSession(
        user_id=user.id,
        token_hash=_digest(raw_token),
        expires_at=now + timedelta(seconds=max_age),
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("User-Agent") or "")[:512] or None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["session_token"] = raw_token
    request.session["csrf_token"] = generate_csrf_token()
    return row


def active_session(request: Request, db: Session) -> PanelSession | None:
    user_id = request.session.get("user_id")
    raw_token = request.session.get("session_token")
    if not user_id or not raw_token:
        return None
    row = db.scalar(select(PanelSession).where(PanelSession.user_id == user_id, PanelSession.token_hash == _digest(raw_token)))
    if not row or row.revoked_at is not None:
        return None
    if _aware(row.expires_at) <= datetime.now(timezone.utc):
        return None
    return row


def revoke_current_session(request: Request, db: Session) -> None:
    row = active_session(request, db)
    if row and row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()
