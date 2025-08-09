import os
import json
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, Query, Request
from fastapi.responses import Response

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
CREDENTIALS_FILE = DATA_DIR / "credentials.json"

# Security constants
SALT_LENGTH = 32
PASSWORD_MIN_LENGTH = 8

class CredentialManager:
    """Secure credential management for Xtreme Codes API."""
    
    def __init__(self):
        """Initialize credential manager with temporary password storage."""
        self._current_password = None  # Temporary storage for new installations
    
    def get_stored_credentials(self) -> Dict[str, Any]:
        """Get credentials from storage (without password)."""
        if CREDENTIALS_FILE.exists():
            try:
                with open(CREDENTIALS_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def get_password_for_display(self) -> Optional[str]:
        """Get password for display in UI (only available after generation)."""
        return self._current_password
    
    def clear_password_cache(self):
        """Clear the cached password (call after displaying to user)."""
        self._current_password = None

# Global instance
_credential_manager = CredentialManager()

def generate_credentials() -> Dict[str, str]:
    """
    Generate unique username and password for this installation.
    
    Returns:
        Dict containing username and password
    """
    # Generate more memorable but still unique credentials
    username = f"toonami_{secrets.token_hex(3)}"  # e.g. toonami_a1b2c3
    password = secrets.token_urlsafe(16)  # Longer, more secure password
    return {"username": username, "password": password}

def hash_password_secure(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Securely hash password with salt using PBKDF2.
    
    Args:
        password: Plain text password to hash
        salt: Optional salt bytes, generates new if None
        
    Returns:
        Tuple of (password_hash_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)
    
    # Use PBKDF2 for secure password hashing
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return password_hash.hex(), salt.hex()

def hash_password(password: str) -> str:
    """
    Simple hash for password storage (backward compatibility).
    
    Args:
        password: Plain text password to hash
        
    Returns:
        SHA256 hash of the password
    """
    return hashlib.sha256(password.encode()).hexdigest()

def load_or_create_credentials() -> Dict[str, Any]:
    """
    Load existing credentials or create new ones.
    
    Returns:
        Dict containing credential information (password only for new installations)
    """
    stored_creds = _credential_manager.get_stored_credentials()
    
    if stored_creds and all(k in stored_creds for k in ["username", "password_hash", "created_at"]):
        # Return existing credentials (without password for security)
        result = dict(stored_creds)
        # Only add password if it's cached (new generation)
        cached_password = _credential_manager.get_password_for_display()
        if cached_password:
            result["password"] = cached_password
        return result
    
    # Generate new credentials - first install or corrupted file
    print("Generating unique Xtreme Codes credentials for first-time setup...")
    new_creds = generate_credentials()
    
    # Store only hashed password and metadata
    stored_creds = {
        "username": new_creds["username"],
        "password_hash": hash_password(new_creds["password"]),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "installation_id": secrets.token_hex(8)
    }
    
    # Save credentials (without plain text password)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(stored_creds, f, indent=2)
    
    print(f"Generated credentials - Username: {stored_creds['username']}")
    print("View full credentials in the WebUI once started")
    
    # Cache password temporarily for display
    _credential_manager._current_password = new_creds["password"]
    
    # Return with temporary password for initial display
    result = dict(stored_creds)
    result["password"] = new_creds["password"]
    return result

def verify_credentials(username: str, password: str) -> bool:
    """
    Verify username and password against stored credentials.
    
    Args:
        username: Username to verify
        password: Password to verify
        
    Returns:
        bool: True if credentials are valid
    """
    stored_creds = _credential_manager.get_stored_credentials()
    return (
        stored_creds.get("username") == username and 
        stored_creds.get("password_hash") == hash_password(password)
    )

def get_server_info(request: Request) -> Dict[str, Any]:
    """
    Generate server info response for Xtreme Codes API.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dict containing server and user information
    """
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

async def xtreme_auth_middleware(
    username: str = Query(None), password: str = Query(None)
) -> Dict[str, str]:
    """
    Middleware to verify Xtreme Codes credentials.
    
    Args:
        username: Username parameter from query
        password: Password parameter from query
        
    Returns:
        Dict containing verified username and password
        
    Raises:
        HTTPException: If authentication fails
    """
    if not username or not password:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not verify_credentials(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"username": username, "password": password}

def generate_short_epg(channels: List[Dict[str, Any]]) -> str:
    """
    Generate simplified EPG data for channels.
    
    Args:
        channels: List of channel dictionaries
        
    Returns:
        JSON string containing EPG data
    """
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

def format_xtreme_m3u(
    channels: List[Dict[str, Any]], host: str, username: str, password: str
) -> str:
    """
    Format M3U for Xtreme Codes API format.
    
    Args:
        channels: List of channel dictionaries
        host: Server hostname
        username: Xtreme Codes username
        password: Xtreme Codes password
        
    Returns:
        M3U formatted string
    """
    lines = ["#EXTM3U"]
    
    for channel in channels:
        ch_id = channel.get("id", "")
        ch_num = channel.get("number", "")
        ch_name = channel.get("name", "")
        
        # Build Xtreme Codes style URL
        stream_url = f"http://{host}/live/{username}/{password}/{ch_id}.ts"
        
        # EXTINF line with Xtreme Codes attributes
        extinf = (
            f'#EXTINF:-1 tvg-id="{ch_id}" tvg-name="{ch_name}" '
            f'tvg-logo="" group-title="Toonami"'
        )
        if ch_num:
            extinf += f' tvg-chno="{ch_num}"'
        extinf += f',{ch_name}'
        
        lines.append(extinf)
        lines.append(stream_url)
    
    return "\n".join(lines)