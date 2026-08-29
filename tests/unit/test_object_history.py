from app.object_history import parse_audit_value, value_diff


def test_parse_json_audit_value():
    assert parse_audit_value('{"mail":"a@example.org"}') == {"mail": "a@example.org"}


def test_parse_plain_audit_value():
    assert parse_audit_value("[REDACTED]") == "[REDACTED]"


def test_dict_diff_reports_added_removed_and_changed():
    changes = value_diff(
        {"mail": "old@example.org", "sn": "Old", "obsolete": True},
        {"mail": "new@example.org", "sn": "Old", "givenName": "Alice"},
    )
    by_attr = {item["attribute"]: item for item in changes}
    assert by_attr["mail"]["change"] == "changed"
    assert by_attr["givenName"]["change"] == "added"
    assert by_attr["obsolete"]["change"] == "removed"
    assert "sn" not in by_attr


def test_scalar_diff():
    assert value_diff("old", "new") == [{"attribute": None, "change": "changed", "old": "old", "new": "new"}]
    assert value_diff("same", "same") == []
