from __future__ import annotations

import json
import secrets
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog

SENSITIVE_NAMES = {"password", "userpassword", "token", "secret", "bind_password", "private_key"}


def redact(attribute: str | None, value: Any) -> str | None:
    if value is None:
        return None
    if attribute and attribute.lower().replace("-", "_") in SENSITIVE_NAMES:
        return "[REDACTED]"
    if isinstance(value, (dict, list, tuple)):
        safe = _redact_structure(value)
        return json.dumps(safe, ensure_ascii=False, default=str)
    return str(value)


def _redact_structure(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "[REDACTED]" if k.lower().replace("-", "_") in SENSITIVE_NAMES else _redact_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_structure(v) for v in value]
    if isinstance(value, tuple):
        return [_redact_structure(v) for v in value]
    return value


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def record(self, *, request_id: str, panel_user: str, source_ip: str | None, operation: str,
               status: str, dn: str | None = None, attribute: str | None = None,
               old_value: Any = None, new_value: Any = None, message: str | None = None) -> str:
        operation_id = "op_" + secrets.token_hex(10)
        row = AuditLog(
            operation_id=operation_id,
            request_id=request_id,
            panel_user=panel_user,
            source_ip=source_ip,
            operation=operation,
            dn=dn,
            attribute=attribute,
            old_value=redact(attribute, old_value),
            new_value=redact(attribute, new_value),
            status=status,
            message=message,
        )
        self.db.add(row)
        self.db.commit()
        return operation_id
