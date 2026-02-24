#!/usr/bin/env python3
"""
Integration tests for Toonami Aftermath Downlink API endpoints.
Basic tests to ensure the API responds correctly to requests.
"""

import shutil
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / "app"))

# Set up test environment
import os

os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEB_DIR"] = str(Path(__file__).parent / "web")

from app.server import app


def test_api_endpoints():
    """Test basic API endpoints."""
    print("🧪 Testing API endpoints...")

    with TestClient(app) as client:
        # Test status endpoint
        response = client.get("/status")
        assert response.status_code == 200, f"Status endpoint failed: {response.status_code}"
        data = response.json()
        assert "channel_count" in data
        assert "cron" in data
        print("✅ Status endpoint working")

        # Test channels endpoint
        response = client.get("/channels")
        assert response.status_code == 200, f"Channels endpoint failed: {response.status_code}"
        channels = response.json()
        assert isinstance(channels, list)
        print("✅ Channels endpoint working")

        # Test credentials endpoint
        response = client.get("/credentials")
        assert (
            response.status_code == 200
        ), f"Credentials endpoint failed: {response.status_code}"
        creds = response.json()
        assert "username" in creds
        assert "server_url" in creds
        assert "password_available" in creds
        if creds["password_available"]:
            assert creds["password"] is not None
        print("✅ Credentials endpoint working")

        # Test M3U endpoint (should fail with 404 since no files generated)
        response = client.get("/m3u")
        assert (
            response.status_code == 404
        ), f"M3U endpoint should return 404: {response.status_code}"
        print("✅ M3U endpoint properly returns 404 when no file exists")

        # Test stream code endpoint (should fail with 404 since no files generated)
        response = client.get("/m3u/stream-codes/test_code")
        assert (
            response.status_code == 404
        ), f"Stream code endpoint should return 404: {response.status_code}"
        print("✅ Stream code endpoint working")

        # Test invalid stream code
        response = client.get("/m3u/stream-codes/invalid@code")
        assert (
            response.status_code == 400
        ), f"Invalid stream code should return 400: {response.status_code}"
        print("✅ Stream code validation working")

        # Test health endpoint
        response = client.get("/health")
        assert response.status_code in [
            200,
            503,
        ], f"Health endpoint failed: {response.status_code}"
        health_data = response.json()
        assert "status" in health_data
        assert "timestamp" in health_data
        assert "checks" in health_data
        print("✅ Health endpoint working")

        # Test stream codes endpoint
        response = client.get("/stream-codes")
        assert (
            response.status_code == 200
        ), f"Stream codes endpoint failed: {response.status_code}"
        stream_codes_data = response.json()
        assert "stream_code_urls" in stream_codes_data
        assert "credentials" in stream_codes_data
        assert "username" in stream_codes_data["credentials"]
        assert "password_available" in stream_codes_data["credentials"]
        assert "password" in stream_codes_data["credentials"]
        if stream_codes_data["credentials"]["password_available"]:
            assert stream_codes_data["credentials"]["password"] is not None
        print("✅ Stream codes endpoint working")


def test_xtreme_codes_api():
    """Test Xtreme Codes API endpoints."""
    print("\n🔐 Testing Xtreme Codes API...")

    with TestClient(app) as client:
        # Test without credentials
        response = client.get("/player_api.php")
        assert (
            response.status_code == 401
        ), f"No auth should return 401: {response.status_code}"
        print("✅ Authentication required for Xtreme Codes API")

        # Test with invalid credentials
        response = client.get("/player_api.php?username=invalid&password=invalid")
        assert (
            response.status_code == 401
        ), f"Invalid auth should return 401: {response.status_code}"
        print("✅ Invalid credentials properly rejected")

        # Get valid credentials from the system
        creds_response = client.get("/credentials")
        creds = creds_response.json()
        username = creds["username"]
        password = creds.get("password", "test_password")  # Fallback for existing installs

        if password and password != "********":
            # Test with valid credentials
            response = client.get(f"/player_api.php?username={username}&password={password}")
            assert (
                response.status_code == 200
            ), f"Valid auth should work: {response.status_code}"
            data = response.json()
            assert "user_info" in data
            assert data["user_info"]["auth"] == 1
            print("✅ Valid credentials accepted")
        else:
            print("⚠️  Skipping valid credential test (password not available)")

        direct_urls = creds.get("direct_urls", {})
        xtreme_m3u_url = direct_urls.get("xtreme_m3u", "")
        if xtreme_m3u_url:
            parsed = urlparse(xtreme_m3u_url)
            qs = parse_qs(parsed.query)
            token = qs.get("token", [None])[0]
            assert "password=" not in xtreme_m3u_url
            assert token is not None and token.strip()
            response = client.get("/get.php", params={"username": username, "token": token})
            assert (
                response.status_code == 200
            ), f"Valid token should return stream URL list: {response.status_code}"
        else:
            print("⚠️  Skipping token validation for Xtreme endpoints")


def test_input_validation():
    """Test input validation and security."""
    print("\n🛡️  Testing input validation...")

    with TestClient(app) as client:
        # Test overly long stream code
        long_code = "a" * 100
        response = client.get(f"/m3u/stream-codes/{long_code}")
        assert (
            response.status_code == 400
        ), f"Long stream code should be rejected: {response.status_code}"
        print("✅ Long stream codes properly rejected")

        # Test special characters in stream code
        special_code = "test$%^&*"
        response = client.get(f"/m3u/stream-codes/{special_code}")
        assert (
            response.status_code == 400
        ), f"Special characters should be rejected: {response.status_code}"
        print("✅ Invalid characters in stream codes rejected")

        # Test empty stream code
        response = client.get("/m3u/stream-codes/")
        assert response.status_code in [
            400,
            404,
        ], f"Empty stream code should be rejected: {response.status_code}"
        print("✅ Empty stream codes handled properly")


def test_refresh_endpoint_requires_auth():
    """Test refresh endpoint access control."""
    with TestClient(app) as client:
        response = client.post("/refresh")
        assert response.status_code in {
            401,
            429,
        }, f"Refresh should be protected, got: {response.status_code}"
        print("✅ Refresh endpoint is protected from anonymous access")


def test_generation_requires_fresh_artifacts():
    """Ensure generation validation rejects stale pre-existing artifacts."""
    from app import server

    server.M3U_PATH.parent.mkdir(parents=True, exist_ok=True)
    server.M3U_PATH.write_text("#EXTM3U\n")
    server.XML_PATH.write_text("<tv></tv>\n")

    stale_mtime = time.time() - 3 * 24 * 60 * 60  # 3 days ago
    os.utime(server.M3U_PATH, (stale_mtime, stale_mtime))
    os.utime(server.XML_PATH, (stale_mtime, stale_mtime))

    assert not server._verify_generated_files(generated_after=time.time())
    print("✅ Stale artifacts are rejected during generation validation")


def test_lan_refresh_host_detection():
    """Ensure LAN/private hosts are treated as local for refresh auth checks."""
    from app import server

    assert server._is_local_host("127.0.0.1")
    assert server._is_local_host("192.168.1.20")
    assert server._is_local_host("10.0.0.45")
    assert server._is_local_host("172.16.0.10")
    assert server._is_local_host("::1")
    assert server._is_local_host("::ffff:192.168.1.40")
    assert not server._is_local_host("8.8.8.8")
    print("✅ LAN/private refresh host detection works as expected")


def test_cron_next_respects_dom_mon_dow():
    """Ensure cron scheduling applies day/month/day-of-week fields."""
    from app import server

    now = datetime(2026, 2, 24, 12, 0, tzinfo=UTC)  # Tuesday

    assert server.cron_next(now, "0 3 1 * *") == datetime(2026, 3, 1, 3, 0, tzinfo=UTC)
    assert server.cron_next(now, "0 3 * 3 *") == datetime(2026, 3, 1, 3, 0, tzinfo=UTC)
    assert server.cron_next(now, "0 3 * * 0") == datetime(2026, 3, 1, 3, 0, tzinfo=UTC)
    # Cron semantics: if both DOM and DOW are restricted, either may match.
    assert server.cron_next(now, "0 3 25 * 0") == datetime(2026, 2, 25, 3, 0, tzinfo=UTC)
    print("✅ Cron scheduling respects day/month/day-of-week fields")


def test_status_reports_cron_and_failure_diagnostics():
    """Status endpoint should expose cron support and last failure metadata."""
    from app import server

    previous_cron = os.environ.get("CRON_SCHEDULE")
    original_scheduler_loop = server.scheduler_loop

    async def noop_scheduler_loop():
        return None

    try:
        os.environ["CRON_SCHEDULE"] = "0 3 * * */2"  # unsupported DOW step syntax
        server.scheduler_loop = noop_scheduler_loop
        failure_time = datetime.now(UTC).isoformat()
        server.write_state(
            {
                "last_update": datetime.now(UTC).isoformat(),
                "last_error": "simulated failure",
                "last_failure_at": failure_time,
                "last_failure_context": "scheduler",
                "consecutive_failures": 2,
            }
        )

        with TestClient(app) as client:
            response = client.get("/status")
            assert response.status_code == 200
            payload = response.json()
            assert payload["cron_supported"] is False
            assert payload["cron_error"] is not None
            assert "Unsupported day-of-week field" in payload["cron_error"]
            assert payload["last_error"] == "simulated failure"
            assert payload["last_failure_at"] == failure_time
            assert payload["last_failure_context"] == "scheduler"
            assert payload["consecutive_failures"] == 2
        print("✅ Status endpoint exposes cron/failure diagnostics")
    finally:
        server.scheduler_loop = original_scheduler_loop
        if previous_cron is None:
            os.environ.pop("CRON_SCHEDULE", None)
        else:
            os.environ["CRON_SCHEDULE"] = previous_cron


def test_record_generation_failure_updates_state():
    """Failure recorder should persist normalized error metadata."""
    from app import server

    server._record_generation_failure(
        RuntimeError("boom"), context="scheduler", consecutive_failures=3
    )
    state = server.read_state()
    assert state["last_error"] == "boom"
    assert state["last_failure_context"] == "scheduler"
    assert state["consecutive_failures"] == 3
    assert state["last_failure_at"]
    print("✅ Failure metadata persistence works")


def test_health_reports_scheduler_failure_state():
    """Health endpoint should degrade when scheduler failures accumulate."""
    from app import server

    original_scheduler_loop = server.scheduler_loop

    async def noop_scheduler_loop():
        return None

    server.scheduler_loop = noop_scheduler_loop
    server.write_state(
        {
            "last_update": datetime.now(UTC).isoformat(),
            "last_error": "scheduler crashed",
            "last_failure_at": datetime.now(UTC).isoformat(),
            "last_failure_context": "scheduler",
            "consecutive_failures": 3,
        }
    )

    try:
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 503
            payload = response.json()
            assert payload["checks"]["scheduler_failures"] == "error"
            assert payload["last_failure"]["consecutive_failures"] == 3
            assert payload["last_failure"]["error"] == "scheduler crashed"
    finally:
        server.scheduler_loop = original_scheduler_loop
    print("✅ Health endpoint marks repeated scheduler failures as unhealthy")


def test_health_reports_stale_freshness():
    """Health endpoint should surface stale artifact freshness details."""
    from app import server

    server.M3U_PATH.parent.mkdir(parents=True, exist_ok=True)
    server.M3U_PATH.write_text("#EXTM3U\n")
    server.XML_PATH.write_text("<tv></tv>\n")

    stale_mtime = time.time() - (3 * 24 * 60 * 60)
    os.utime(server.M3U_PATH, (stale_mtime, stale_mtime))
    os.utime(server.XML_PATH, (stale_mtime, stale_mtime))
    server.write_state(
        {"last_update": datetime.fromtimestamp(stale_mtime, tz=UTC).isoformat()}
    )

    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code in {200, 503}
        payload = response.json()
        assert "freshness" in payload
        assert payload["freshness"]["is_stale"] is True
        assert payload["checks"]["artifact_freshness"] in {"warning", "error"}
    print("✅ Health endpoint reports stale guide freshness")


def test_watchdog_recovery_triggers_when_stale():
    """Watchdog should trigger immediate recovery generation for stale data."""
    import asyncio

    from app import server

    stale_time = datetime.now(UTC) - timedelta(days=3)
    server.write_state({"last_update": stale_time.isoformat()})
    server.app.state.last_stale_recovery_attempt = 0.0
    server.app.state.generation_task = None

    calls = {"count": 0}
    original = server._run_generate_files_serialized
    original_cooldown = server.STALE_RECOVERY_COOLDOWN_SECONDS
    original_generation_in_progress = server._generation_in_progress

    async def fake_generate():
        calls["count"] += 1
        server.write_state({"last_update": datetime.now(UTC).isoformat()})
        return {"ok": True}

    try:
        server.STALE_RECOVERY_COOLDOWN_SECONDS = 0
        server._generation_in_progress = lambda: False
        server._run_generate_files_serialized = fake_generate
        triggered = asyncio.run(server._run_stale_recovery_if_needed(datetime.now(UTC)))
        assert triggered is True
        assert calls["count"] == 1
    finally:
        server.STALE_RECOVERY_COOLDOWN_SECONDS = original_cooldown
        server._run_generate_files_serialized = original
        server._generation_in_progress = original_generation_in_progress
    print("✅ Stale-data watchdog triggers recovery refresh")


def cleanup():
    """Clean up test data directory."""
    data_dir = os.environ.get("DATA_DIR")
    if data_dir and Path(data_dir).exists():
        shutil.rmtree(data_dir)
        print(f"🧹 Cleaned up test directory: {data_dir}")


def main():
    """Run all integration tests."""
    print("🚀 Toonami Aftermath: Downlink - Integration Tests")
    print("=" * 60)

    try:
        test_api_endpoints()
        test_xtreme_codes_api()
        test_input_validation()
        test_generation_requires_fresh_artifacts()
        test_lan_refresh_host_detection()
        test_cron_next_respects_dom_mon_dow()
        test_status_reports_cron_and_failure_diagnostics()
        test_record_generation_failure_updates_state()
        test_health_reports_scheduler_failure_state()
        test_health_reports_stale_freshness()
        test_watchdog_recovery_triggers_when_stale()

        print("\n🎉 All integration tests passed!")
        print("✅ API endpoints are working correctly")
        print("✅ Authentication and authorization working")
        print("✅ Input validation protecting against invalid inputs")

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
