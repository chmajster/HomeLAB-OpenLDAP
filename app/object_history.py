from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import AuditLog


def parse_audit_value(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def value_diff(old: Any, new: Any) -> list[dict[str, Any]]:
    if isinstance(old, dict) or isinstance(new, dict):
        old_map = old if isinstance(old, dict) else {}
        new_map = new if isinstance(new, dict) else {}
        changes: list[dict[str, Any]] = []
        for key in sorted(set(old_map) | set(new_map)):
            before = old_map.get(key)
            after = new_map.get(key)
            if before == after:
                continue
            if key not in old_map:
                change = "added"
            elif key not in new_map:
                change = "removed"
            else:
                change = "changed"
            changes.append({"attribute": key, "change": change, "old": before, "new": after})
        return changes
    if old == new:
        return []
    return [{"attribute": None, "change": "changed", "old": old, "new": new}]


class ObjectHistoryService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def serialize(row: AuditLog) -> dict[str, Any]:
        old_value = parse_audit_value(row.old_value)
        new_value = parse_audit_value(row.new_value)
        return {
            "id": row.id,
            "operation_id": row.operation_id,
            "request_id": row.request_id,
            "created_at": row.created_at,
            "panel_user": row.panel_user,
            "source_ip": row.source_ip,
            "operation": row.operation,
            "dn": row.dn,
            "attribute": row.attribute,
            "status": row.status,
            "message": row.message,
            "old_value": old_value,
            "new_value": new_value,
            "diff": value_diff(old_value, new_value),
        }

    def timeline(
        self,
        dn: str,
        *,
        operation: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        query = select(AuditLog).where(AuditLog.dn == dn)
        if operation:
            query = query.where(AuditLog.operation == operation)
        if status:
            query = query.where(AuditLog.status == status)
        rows = list(self.db.scalars(query.order_by(desc(AuditLog.created_at)).limit(min(max(limit, 1), 500))).all())
        items = [self.serialize(row) for row in rows]
        operations = Counter(row.operation for row in rows)
        actors = Counter(row.panel_user for row in rows)
        timestamps = [row.created_at for row in rows]
        return {
            "dn": dn,
            "summary": {
                "events": len(rows),
                "success": sum(1 for row in rows if str(row.status).upper() == "SUCCESS"),
                "failed": sum(1 for row in rows if str(row.status).upper() not in {"SUCCESS", "COMPLETED"}),
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "operations": dict(operations.most_common()),
                "actors": dict(actors.most_common()),
            },
            "items": items,
        }
