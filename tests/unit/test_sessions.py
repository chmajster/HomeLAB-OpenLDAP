from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.database import Base
from app.models import PanelUser
from app.session_store import active_session, establish_session, revoke_current_session


def make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"user-agent", b"pytest")],
        "client": ("127.0.0.1", 12345),
        "session": {},
    }
    return Request(scope)


def test_server_side_session_lifecycle():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = PanelUser(username="session-user", password_hash="not-used", role="Read Only")
        db.add(user)
        db.commit()
        db.refresh(user)
        request = make_request()
        created = establish_session(request, db, user, 3600)
        assert created.user_id == user.id
        assert request.session["user_id"] == user.id
        assert active_session(request, db) is not None
        revoke_current_session(request, db)
        assert active_session(request, db) is None
