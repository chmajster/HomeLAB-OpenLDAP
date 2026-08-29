import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.dependencies import _requested_server_id
from app.server_web import _safe_next


def make_request(*, server_header: str | None = None, session: dict | None = None) -> Request:
    headers = []
    if server_header is not None:
        headers.append((b"x-ldap-server-id", server_header.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/users",
            "headers": headers,
            "query_string": b"",
            "session": session if session is not None else {},
        }
    )


def test_header_server_id_has_priority_over_session():
    request = make_request(server_header="7", session={"ldap_server_id": 3})
    assert _requested_server_id(request) == (7, "header")


def test_session_server_id_is_used_when_header_is_missing():
    request = make_request(session={"ldap_server_id": "4"})
    assert _requested_server_id(request) == (4, "session")


def test_invalid_header_is_rejected():
    request = make_request(server_header="production")
    with pytest.raises(HTTPException) as exc:
        _requested_server_id(request)
    assert exc.value.status_code == 422


def test_invalid_session_selection_is_cleared():
    session = {"ldap_server_id": "bad"}
    request = make_request(session=session)
    assert _requested_server_id(request) == (None, None)
    assert "ldap_server_id" not in session


def test_server_switch_redirect_rejects_external_or_protocol_relative_urls():
    assert _safe_next("https://example.org") == "/dashboard"
    assert _safe_next("//example.org") == "/dashboard"
    assert _safe_next("/groups") == "/groups"
