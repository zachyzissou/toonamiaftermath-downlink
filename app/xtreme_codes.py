import os
import json
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, Query, Request
from fastapi.responses import Response

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
CREDENTIALS_FILE = DATA_DIR / "credentials.json"

def generate_credentials() -> Dict[str, str]:
    """Generate unique username and password for this installation."""
    # Generate more memorable but still unique credentials
    username = f"toonami_{secrets.token_hex(3)}"  # e.g. toonami_a1b2c3
    password = secrets.token_urlsafe(16)  # Longer, more secure password
    return {"username": username, "password": password}

def hash_password(password: str) -> str:
    """Simple hash for password storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_or_create_credentials() -> Dict[str, str]:
    """Load existing credentials or create new ones."""
    if CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                creds = json.load(f)
                # Ensure we have all required fields
                if all(k in creds for k in ["username", "password", "password_hash", "created_at"]):
                    return creds
        except Exception:
            pass
    
    # Generate new credentials - first install or corrupted file
    print("Generating unique Xtreme Codes credentials for first-time setup...")
    creds = generate_credentials()
    creds["password_hash"] = hash_password(creds["password"])
    creds["created_at"] = datetime.now(timezone.utc).isoformat()
    creds["installation_id"] = secrets.token_hex(8)  # Unique installation ID
    
    # Save credentials
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)
    
    print(f"Generated credentials - Username: {creds['username']}")
    print("View full credentials in the WebUI once started")
    
    return creds

def verify_credentials(username: str, password: str) -> bool:
    """Verify username and password."""
    creds = load_or_create_credentials()
    return (
        creds.get("username") == username and 
        creds.get("password_hash") == hash_password(password)
    )

def get_server_info(request: Request) -> Dict[str, Any]:
    """Generate server info response."""
    host = request.headers.get("host", "localhost")
    protocol = "https" if request.url.scheme == "https" else "http"
    
    return {
        "user_info": {
            "username": request.state.username if hasattr(request.state, "username") else "",
            "password": request.state.password if hasattr(request.state, "password") else "",
            "message": "Toonami Aftermath: Downlink",
            "auth": 1,
            "status": "Active",
            "exp_date": "2099-12-31",
            "is_trial": "0",
            "active_cons": "1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "max_connections": "1",
            "allowed_output_formats": ["m3u8", "ts", "rtmp"]
        },
        "server_info": {
            "url": f"{protocol}://{host}",
            "port": request.url.port or (443 if protocol == "https" else 80),
            "https_port": 443 if protocol == "https" else None,
            "server_protocol": protocol,
            "rtmp_port": 1935,
            "timezone": "UTC",
            "timestamp_now": int(datetime.now(timezone.utc).timestamp()),
            "time_now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        }
    }

async def xtreme_auth_middleware(username: str = Query(None), password: str = Query(None)):
    """Middleware to verify Xtreme Codes credentials."""
    if not username or not password:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not verify_credentials(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"username": username, "password": password}

def generate_short_epg(channels: list) -> str:
    """Generate simplified EPG data."""
    epg_data = {
        "epg_listings": []
    }
    
    now = datetime.now(timezone.utc)
    for channel in channels:
        # Create dummy EPG data for each channel
        epg_data["epg_listings"].append({
            "channel_id": channel.get("id", ""),
            "epg_id": channel.get("id", ""),
            "title": "Toonami Aftermath Stream",
            "start": now.isoformat(),
            "end": (now + timedelta(hours=24)).isoformat(),
            "description": f"Now streaming: {channel.get('name', 'Unknown')}"
        })
    
    return json.dumps(epg_data)

def format_xtreme_m3u(channels: list, host: str, username: str, password: str) -> str:
    """Format M3U for Xtreme Codes API format."""
    lines = ["#EXTM3U"]
    
    for channel in channels:
        ch_id = channel.get("id", "")
        ch_num = channel.get("number", "")
        ch_name = channel.get("name", "")
        
        # Build Xtreme Codes style URL
        stream_url = f"http://{host}/live/{username}/{password}/{ch_id}.ts"
        
        # EXTINF line with Xtreme Codes attributes
        extinf = f'#EXTINF:-1 tvg-id="{ch_id}" tvg-name="{ch_name}" tvg-logo="" group-title="Toonami"'
        if ch_num:
            extinf += f' tvg-chno="{ch_num}"'
        extinf += f',{ch_name}'
        
        lines.append(extinf)
        lines.append(stream_url)
    
    return "\n".join(lines)