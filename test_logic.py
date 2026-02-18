import importlib
import json
import sys

import pytest


def _reload_module(module_name: str):
    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


def test_credential_generation_writes_secure_metadata(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    xtreme = _reload_module("app.xtreme_codes")
    creds = xtreme.load_or_create_credentials()

    assert creds["username"].startswith("toonami_")
    assert "password" not in creds
    assert "recovery_code" not in creds
    assert isinstance(xtreme._credential_manager.pop_password_for_display(), str)
    assert isinstance(xtreme._credential_manager.pop_recovery_code_for_display(), str)

    stored = json.loads((data_dir / "credentials.json").read_text())
    assert "password_salt" in stored
    assert "pbkdf2_iterations" in stored
    assert "recovery_code_hash" in stored
    assert stored.get("hash_algorithm") == "pbkdf2_sha256"

    recovery_file = data_dir / "credentials.recovery"
    assert recovery_file.exists()


def test_legacy_hash_is_migrated_on_successful_auth(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    xtreme = _reload_module("app.xtreme_codes")

    username = "legacy_user"
    password = "legacy-password"
    legacy = {
        "username": username,
        "password_hash": xtreme.hash_password(password),
        "created_at": "2025-01-01T00:00:00+00:00",
        "installation_id": "legacy-install",
    }
    (data_dir / "credentials.json").write_text(json.dumps(legacy))

    assert xtreme.verify_credentials(username, password) is True

    migrated = json.loads((data_dir / "credentials.json").read_text())
    assert migrated["password_hash"] != legacy["password_hash"]
    assert "password_salt" in migrated
    assert migrated.get("hash_algorithm") == "pbkdf2_sha256"


def test_parse_extinf_handles_expected_fields(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    web_dir = tmp_path / "web"
    assets_dir = web_dir / "assets"
    assets_dir.mkdir(parents=True)
    (web_dir / "index.html").write_text("<html></html>")

    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WEB_DIR", str(web_dir))

    server = _reload_module("app.server")

    line = '#EXTINF:-1 tvg-id="toonami1" tvg-chno="1" tvg-name="Toonami 1",Toonami Channel 1'
    channel_id, number, name = server._parse_extinf(line)

    assert channel_id == "toonami1"
    assert number == "1"
    assert name == "Toonami Channel 1"


def test_invalid_credentials_file_raises_storage_error(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    xtreme = _reload_module("app.xtreme_codes")
    (data_dir / "credentials.json").write_text("{bad json")

    with pytest.raises(xtreme.CredentialStorageError):
        xtreme.load_or_create_credentials()


def test_pbkdf2_iteration_value_is_clamped(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    xtreme = _reload_module("app.xtreme_codes")
    creds = xtreme.load_or_create_credentials()
    password = xtreme._credential_manager.pop_password_for_display()
    assert isinstance(password, str)

    stored = json.loads((data_dir / "credentials.json").read_text())
    stored["pbkdf2_iterations"] = "not-a-number"
    (data_dir / "credentials.json").write_text(json.dumps(stored))
    assert xtreme.verify_credentials(creds["username"], password) is True

    stored["pbkdf2_iterations"] = -10
    (data_dir / "credentials.json").write_text(json.dumps(stored))
    assert xtreme.verify_credentials(creds["username"], password) is True
