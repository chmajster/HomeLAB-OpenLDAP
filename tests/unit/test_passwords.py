import base64

from app.ldap.services import LDAPPasswordService


def test_ssha_format_contains_salt():
    value = LDAPPasswordService.hash_ssha("LongEnoughPassword")
    assert value.startswith("{SSHA}")
    raw = base64.b64decode(value[6:])
    assert len(raw) > 20


def test_password_generator_respects_length():
    value = LDAPPasswordService.generate(32)
    assert len(value) == 32
    assert any(c.isupper() for c in value)
    assert any(c.islower() for c in value)
    assert any(c.isdigit() for c in value)
