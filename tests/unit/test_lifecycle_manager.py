from datetime import date

from app.lifecycle_manager import LDAPLifecycleManagerService


def test_classify_active_account():
    result = LDAPLifecycleManagerService.classify({"username": "alice"}, today=date(2026, 8, 29))
    assert result["state"] == "active"
    assert result["password_reset_required"] is False


def test_classify_locked_has_priority():
    result = LDAPLifecycleManagerService.classify(
        {"pwdAccountLockedTime": ["20260829000000Z"], "shadowExpire": ["20000"]},
        today=date(2026, 8, 29),
    )
    assert result["state"] == "locked"
    assert result["locked"] is True


def test_classify_expired_and_password_reset():
    result = LDAPLifecycleManagerService.classify(
        {"shadowExpire": ["1"], "pwdReset": ["TRUE"]},
        today=date(2026, 8, 29),
    )
    assert result["state"] == "expired"
    assert result["password_reset_required"] is True


def test_classify_expiring_within_30_days():
    days = (date(2026, 9, 10) - date(1970, 1, 1)).days
    result = LDAPLifecycleManagerService.classify({"shadowExpire": [str(days)]}, today=date(2026, 8, 29))
    assert result["state"] == "expiring"
    assert result["expires_on"] == "2026-09-10"
