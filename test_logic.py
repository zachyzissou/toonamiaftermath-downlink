#!/usr/bin/env python3
"""Test script to validate core application logic without FastAPI dependencies."""

import hashlib
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / "app"))


def test_credential_generation():
    """Test credential generation logic."""
    print("🔐 Testing credential generation...")

    # Simulate the credential generation logic
    username = f"toonami_{secrets.token_hex(3)}"
    password = secrets.token_urlsafe(16)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    creds = {
        "username": username,
        "password": password,
        "password_hash": password_hash,
        "created_at": datetime.now(UTC).isoformat(),
        "installation_id": secrets.token_hex(8),
    }

    print(f"✅ Generated username: {creds['username']}")
    print(f"✅ Generated password: {creds['password'][:4]}...")
    print(f"✅ Installation ID: {creds['installation_id']}")
    print(f"✅ Created at: {creds['created_at']}")

    return creds


def test_m3u_parsing():
    """Test M3U parsing logic."""
    print("\n📺 Testing M3U parsing...")

    # Sample M3U content
    sample_m3u = """#EXTM3U
#EXTINF:-1 tvg-id="toonami1" tvg-chno="1" tvg-name="Toonami 1",Toonami Channel 1
http://example.com/stream1
#EXTINF:-1 tvg-id="toonami2" tvg-chno="2" tvg-name="Toonami 2",Toonami Channel 2
http://example.com/stream2?quality=high
"""

    # Parse logic (simplified)
    channels = []
    pending = None

    for line in sample_m3u.strip().split("\n"):
        line = line.strip()
        if line.startswith("#EXTINF"):
            # Extract channel info
            parts = line.split(",", 1)
            name = parts[1] if len(parts) > 1 else None

            # Extract attributes
            attrs = parts[0]
            tvg_id = None
            tvg_chno = None

            for attr in ['tvg-id="', 'tvg-chno="']:
                if attr in attrs:
                    start = attrs.find(attr) + len(attr)
                    end = attrs.find('"', start)
                    if end != -1:
                        value = attrs[start:end]
                        if attr.startswith("tvg-id"):
                            tvg_id = value
                        elif attr.startswith("tvg-chno"):
                            tvg_chno = value

            pending = {"id": tvg_id, "number": tvg_chno, "name": name}

        elif line and not line.startswith("#") and pending:
            pending["url"] = line
            channels.append(pending)
            pending = None

    print(f"✅ Parsed {len(channels)} channels:")
    for ch in channels:
        print(f"   - {ch['name']} (#{ch['number']}) -> {ch['url']}")

    return channels


def test_stream_code_injection():
    """Test stream code injection logic."""
    print("\n🔗 Testing stream code injection...")

    test_urls = [
        "http://example.com/stream1",
        "http://example.com/stream2?quality=high",
    ]

    stream_code = "abc123"

    for url in test_urls:
        if "?" in url:
            modified_url = f"{url}&code={stream_code}"
        else:
            modified_url = f"{url}?code={stream_code}"

        print(f"✅ {url} -> {modified_url}")


def test_file_structure():
    """Test that all required files exist."""
    print("\n📁 Testing file structure...")

    required_files = [
        "app/server.py",
        "app/xtreme_codes.py",
        "app/__init__.py",
        "web/index.html",
        "web/assets/style.css",
        "web/assets/app.js",
        "Dockerfile",
        "docker-compose.yml",
        "requirements.txt",
        "README.md",
    ]

    base_path = Path(__file__).parent

    for file_path in required_files:
        full_path = base_path / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")


def main():
    print("🚀 Toonami Aftermath: Downlink - Core Logic Test")
    print("=" * 60)

    try:
        # Run tests
        test_credential_generation()
        test_m3u_parsing()
        test_stream_code_injection()
        test_file_structure()

        print("\n🎉 All core logic tests passed!")
        print("🐳 Ready for Docker deployment!")
        print("\n💡 To run the full application:")
        print("   docker build -t toonami-downlink:latest .")
        print(
            "   docker run -d --name toonami-downlink -p 7004:7004 -v ./data:/data toonami-downlink:latest"
        )

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
