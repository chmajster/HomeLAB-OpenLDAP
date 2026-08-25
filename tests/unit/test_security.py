from app.audit import redact
from app.security import generate_api_token, hash_api_token, hash_password, verify_password


def test_argon2_password_hash_roundtrip():
    password = "CorrectHorseBatteryStaple!"
    digest = hash_password(password)
    assert password not in digest
    assert verify_password(password, digest)
    assert not verify_password("wrong", digest)


def test_api_token_is_high_entropy_and_hash_only():
    token = generate_api_token()
    assert token.startswith("hlldap_")
    assert len(hash_api_token(token)) == 64
    assert token not in hash_api_token(token)


def test_audit_redacts_passwords():
    assert redact("userPassword", "secret") == "[REDACTED]"
    assert "secret" not in redact(None, {"password": "secret", "mail": "a@example.local"})
