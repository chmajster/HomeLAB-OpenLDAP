from __future__ import annotations

import hashlib
import hmac
import secrets
from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet, InvalidToken
from passlib.context import CryptContext

from app.config import get_settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def _fernet() -> Fernet:
    settings = get_settings()
    if settings.encryption_key:
        key = settings.encryption_key.encode()
    else:
        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key = urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Cannot decrypt stored secret with current ENCRYPTION_KEY") from exc


def generate_api_token() -> str:
    return "hlldap_" + secrets.token_urlsafe(36)


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_token_match(token: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_api_token(token), expected_hash)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)
