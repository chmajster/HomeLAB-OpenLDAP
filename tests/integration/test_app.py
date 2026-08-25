import os
from pathlib import Path

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test-homelab-openldap.db")
os.environ.setdefault("SESSION_HTTPS_ONLY", "false")

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


def test_health_is_available_without_authentication():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["application"] == "ok"


def test_version_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/version")
        assert response.status_code == 200
        assert "version" in response.json()


def teardown_module():
    Path("test-homelab-openldap.db").unlink(missing_ok=True)
