import importlib
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _reset_modules() -> None:
    for name in ("app.server", "app.xtreme_codes"):
        if name in sys.modules:
            del sys.modules[name]


@pytest.fixture
def app_client(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    web_dir = Path(__file__).parent / "web"
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WEB_DIR", str(web_dir))
    monkeypatch.setenv("CRON_SCHEDULE", "0 3 * * *")

    _reset_modules()
    server = importlib.import_module("app.server")

    async def scheduler_noop():
        return

    monkeypatch.setattr(server, "scheduler_loop", scheduler_noop)

    with TestClient(server.app) as client:
        yield client, server, data_dir


def test_api_endpoints(app_client):
    client, _, _ = app_client

    response = client.get("/status")
    assert response.status_code == 200
    status_data = response.json()
    assert "channel_count" in status_data
    assert "cron" in status_data

    response = client.get("/channels")
    assert response.status_code == 200
    channels = response.json()
    assert isinstance(channels, list)

    response = client.get("/credentials")
    assert response.status_code == 200
    creds = response.json()
    assert "username" in creds
    assert "server_url" in creds
    assert "password_available" in creds
    assert creds["recovery"]["file_path"] == "credentials.recovery"

    response = client.get("/m3u")
    assert response.status_code == 404

    response = client.get("/m3u/stream-codes/test_code")
    assert response.status_code == 404

    response = client.get("/m3u/stream-codes/invalid@code")
    assert response.status_code == 400


def test_xtreme_codes_auth_flow(app_client):
    client, _, _ = app_client

    response = client.get("/player_api.php")
    assert response.status_code == 401

    response = client.get("/player_api.php?username=invalid&password=invalid")
    assert response.status_code == 401

    creds = client.get("/credentials").json()
    username = creds["username"]
    password = creds.get("password")

    assert password

    response = client.get(f"/player_api.php?username={username}&password={password}")
    assert response.status_code == 200
    data = response.json()
    assert "user_info" in data
    assert data["user_info"]["auth"] == 1


def test_rotate_credentials_with_recovery_code(app_client):
    client, _, data_dir = app_client

    creds = client.get("/credentials").json()
    recovery_code = creds.get("recovery_code")
    assert recovery_code

    unauthorized = client.post("/credentials/rotate", json={})
    assert unauthorized.status_code == 401

    wrong_code = client.post(
        "/credentials/rotate", json={"recovery_code": "not-correct"}
    )
    assert wrong_code.status_code == 401

    rotate = client.post(
        "/credentials/rotate",
        json={"recovery_code": recovery_code, "new_password": "new-pass-1234"},
    )
    assert rotate.status_code == 200

    rotated = rotate.json()
    assert rotated["username"] == creds["username"]
    assert rotated["password"] == "new-pass-1234"
    assert rotated.get("recovery_code")
    assert rotated["recovery_file"] == "credentials.recovery"

    auth = client.get(
        f"/player_api.php?username={rotated['username']}&password={rotated['password']}"
    )
    assert auth.status_code == 200

    stored = json.loads((data_dir / "credentials.json").read_text())
    assert "password_salt" in stored
    assert stored.get("hash_algorithm") == "pbkdf2_sha256"


def test_credentials_endpoint_consumes_password_once(app_client):
    client, _, _ = app_client

    first = client.get("/credentials")
    assert first.status_code == 200
    first_data = first.json()
    assert first_data["password_available"] is True
    assert isinstance(first_data["password"], str)

    second = client.get("/credentials")
    assert second.status_code == 200
    second_data = second.json()
    assert second_data["password_available"] is False
    assert second_data["password"] is None


def test_refresh_failure_path_surfaces_in_task(app_client, monkeypatch):
    client, server, _ = app_client

    async def fail_generate_files():
        raise RuntimeError("forced-refresh-failure")

    monkeypatch.setattr(server, "generate_files", fail_generate_files)

    response = client.post("/refresh")
    assert response.status_code == 200
    assert response.json() == {"ok": True}

    task = None
    for _ in range(50):
        task = getattr(server.app.state, "last_refresh_task", None)
        if task and task.done():
            break
        time.sleep(0.02)

    assert task is not None
    assert task.done() is True
    assert isinstance(task.exception(), RuntimeError)


def test_input_validation(app_client):
    client, _, _ = app_client

    long_code = "a" * 100
    response = client.get(f"/m3u/stream-codes/{long_code}")
    assert response.status_code == 400

    response = client.get("/m3u/stream-codes/test$%^&*")
    assert response.status_code == 400

    response = client.get("/m3u/stream-codes/")
    assert response.status_code in [400, 404]
