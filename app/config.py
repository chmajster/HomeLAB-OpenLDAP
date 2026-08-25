from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "HomeLAB OpenLDAP Manager"
    app_env: str = "production"
    web_listen_address: str = "127.0.0.1"
    web_port: int = 8080
    database_url: str = "sqlite:///./homelab-openldap.db"
    secret_key: str = Field(default="dev-change-me")
    encryption_key: str | None = None
    session_https_only: bool = True
    session_max_age: int = 3600
    enable_docs: bool = False
    log_level: str = "INFO"

    ldap_url: str | None = None
    ldap_base_dn: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_starttls: bool = False
    ldap_verify_tls: bool = True
    ldap_ca_cert: str | None = None
    ldap_connect_timeout: int = 10
    ldap_cache_ttl: int = 300
    users_base_dn: str | None = None
    groups_base_dn: str | None = None
    uid_min: int = 10000
    uid_max: int = 60000
    gid_min: int = 10000
    gid_max: int = 60000

    @field_validator("web_port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("WEB_PORT must be between 1 and 65535")
        return value

    @field_validator("ldap_cache_ttl")
    @classmethod
    def validate_cache_ttl(cls, value: int) -> int:
        if not 10 <= value <= 86400:
            raise ValueError("LDAP_CACHE_TTL must be between 10 and 86400 seconds")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def version(self) -> str:
        version_file = Path(__file__).resolve().parents[1] / "VERSION"
        return version_file.read_text(encoding="utf-8").strip() if version_file.exists() else "0.0.0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
