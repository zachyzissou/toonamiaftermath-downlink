import hashlib
import json
import logging
import os
import secrets
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Query, Request

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
CREDENTIALS_FILE = DATA_DIR / "credentials.json"
RECOVERY_FILE = DATA_DIR / "credentials.recovery"

# Security constants
SALT_LENGTH = 32
PASSWORD_MIN_LENGTH = 8
PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 1_000_000
STREAM_TOKEN_BYTES = 24

logger = logging.getLogger(__name__)


class CredentialStorageError(RuntimeError):
    """Raised when credential storage cannot be safely read."""


class CredentialManager:
    """Secure credential management for Xtreme Codes API."""

    def __init__(self):
        """Initialize credential manager with temporary secret storage."""
        self._current_password: str | None = None
        self._current_recovery_code: str | None = None

    def get_stored_credentials(self) -> dict[str, Any]:
        """Get credentials from storage (without plaintext password)."""
        if not CREDENTIALS_FILE.exists():
            return {}

        try:
            with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed reading credentials file %s: %s", CREDENTIALS_FILE, exc)
            raise CredentialStorageError(
                "credentials.json is unreadable or invalid; manual recovery required"
            ) from exc

        if not isinstance(loaded, dict):
            logger.error("Invalid credentials file format in %s", CREDENTIALS_FILE)
            raise CredentialStorageError("credentials.json must contain a JSON object")

        return loaded

    def get_password_for_display(self) -> str | None:
        """Get password for one-time display in UI."""
        return self._current_password

    def pop_password_for_display(self) -> str | None:
        """Consume password for one-time display in UI."""
        password = self._current_password
        self._current_password = None
        return password

    def clear_password_cache(self) -> None:
        """Clear cached plaintext password."""
        self._current_password = None

    def get_recovery_code_for_display(self) -> str | None:
        """Get recovery code for one-time display in UI."""
        return self._current_recovery_code

    def pop_recovery_code_for_display(self) -> str | None:
        """Consume recovery code for one-time display in UI."""
        recovery_code = self._current_recovery_code
        self._current_recovery_code = None
        return recovery_code

    def clear_recovery_code_cache(self) -> None:
        """Clear cached recovery code."""
        self._current_recovery_code = None

    def cache_plaintext_secrets(
        self, *, password: str | None = None, recovery_code: str | None = None
    ) -> None:
        """Store one-time secrets for later consumption by API responses."""
        if password is not None:
            self._current_password = password
        if recovery_code is not None:
            self._current_recovery_code = recovery_code


# Global instance
_credential_manager = CredentialManager()


def _save_stored_credentials(stored_creds: dict[str, Any]) -> None:
    """Persist credentials safely to disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(DATA_DIR),
            prefix="credentials.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            json.dump(stored_creds, tmp, indent=2)
            tmp.write("\n")
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_path = Path(tmp.name)

        temp_path.replace(CREDENTIALS_FILE)
        with suppress(Exception):
            CREDENTIALS_FILE.chmod(0o600)
    finally:
        if temp_path is not None:
            with suppress(FileNotFoundError):
                temp_path.unlink()


def _write_recovery_code_file(recovery_code: str) -> None:
    """Write recovery code to a local recovery file for operator recovery."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RECOVERY_FILE.write_text(
        f"{recovery_code}\n"
        "Use this recovery code with POST /credentials/rotate to rotate credentials.\n"
    )
    with suppress(Exception):
        # Best effort across platforms/filesystems.
        RECOVERY_FILE.chmod(0o600)


def generate_credentials() -> dict[str, str]:
    """
    Generate unique username and password for this installation.

    Returns:
        Dict containing username and password
    """
    username = f"toonami_{secrets.token_hex(3)}"
    password = secrets.token_urlsafe(16)
    return {"username": username, "password": password}


def generate_recovery_code() -> str:
    """Generate a recovery code for credential rotation."""
    return secrets.token_urlsafe(18)


def hash_recovery_code(recovery_code: str) -> str:
    """Hash recovery code for storage."""
    return hashlib.sha256(recovery_code.encode()).hexdigest()


def hash_password_secure(password: str, salt: bytes | None = None) -> tuple[str, str]:
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

    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return password_hash.hex(), salt.hex()


def hash_password(password: str) -> str:
    """
    Legacy hash for backward compatibility.

    Args:
        password: Plain text password to hash

    Returns:
        SHA256 hash of the password
    """
    return hashlib.sha256(password.encode()).hexdigest()


def _is_pbkdf2_record(stored_creds: dict[str, Any]) -> bool:
    """Check if stored credential record uses PBKDF2 metadata."""
    return bool(stored_creds.get("password_salt"))


def _normalize_stored_credentials(
    stored_creds: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    """Ensure required metadata exists; return possibly updated record and optional new recovery code."""
    updated = dict(stored_creds)
    changed = False
    recovery_code_for_display: str | None = None

    if "installation_id" not in updated:
        updated["installation_id"] = secrets.token_hex(8)
        changed = True

    if "recovery_code_hash" not in updated:
        recovery_code_for_display = generate_recovery_code()
        updated["recovery_code_hash"] = hash_recovery_code(recovery_code_for_display)
        _write_recovery_code_file(recovery_code_for_display)
        changed = True

    if "stream_token" not in updated:
        updated["stream_token"] = secrets.token_urlsafe(STREAM_TOKEN_BYTES)
        changed = True

    if changed:
        _save_stored_credentials(updated)

    return updated, recovery_code_for_display


def load_or_create_credentials() -> dict[str, Any]:
    """
    Load existing credentials or create new ones.

    Returns:
        Dict containing credential information (password/recovery only for one-time display)
    """
    stored_creds = _credential_manager.get_stored_credentials()

    if stored_creds and all(
        k in stored_creds for k in ["username", "password_hash", "created_at"]
    ):
        stored_creds, recovery_code_for_display = _normalize_stored_credentials(stored_creds)
        if recovery_code_for_display:
            _credential_manager.cache_plaintext_secrets(
                recovery_code=recovery_code_for_display
            )

        return dict(stored_creds)

    print("Generating unique Xtreme Codes credentials for first-time setup...")
    new_creds = generate_credentials()
    recovery_code = generate_recovery_code()

    password_hash, password_salt = hash_password_secure(new_creds["password"])
    stored_creds = {
        "username": new_creds["username"],
        "password_hash": password_hash,
        "password_salt": password_salt,
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "hash_algorithm": "pbkdf2_sha256",
        "recovery_code_hash": hash_recovery_code(recovery_code),
        "created_at": datetime.now(UTC).isoformat(),
        "installation_id": secrets.token_hex(8),
    }

    _save_stored_credentials(stored_creds)
    _write_recovery_code_file(recovery_code)

    print(f"Generated credentials - Username: {stored_creds['username']}")
    print("View full credentials and recovery code in the WebUI once started")

    _credential_manager.cache_plaintext_secrets(
        password=new_creds["password"], recovery_code=recovery_code
    )
    return dict(stored_creds)


def _verify_pbkdf2_password(stored_creds: dict[str, Any], password: str) -> bool:
    """Verify password against PBKDF2 hash metadata."""
    salt_hex = stored_creds.get("password_salt")
    hash_hex = stored_creds.get("password_hash", "")
    if not salt_hex or not hash_hex:
        return False

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False

    raw_iterations = stored_creds.get("pbkdf2_iterations", PBKDF2_ITERATIONS)
    try:
        iterations = int(raw_iterations)
    except (TypeError, ValueError):
        iterations = PBKDF2_ITERATIONS

    if iterations <= 0:
        iterations = PBKDF2_ITERATIONS
    iterations = min(iterations, MAX_PBKDF2_ITERATIONS)

    candidate_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()
    return secrets.compare_digest(candidate_hash, hash_hex)


def _upgrade_legacy_password_hash(stored_creds: dict[str, Any], password: str) -> None:
    """Upgrade legacy SHA256 password records to PBKDF2 on successful auth."""
    password_hash, password_salt = hash_password_secure(password)
    stored_creds["password_hash"] = password_hash
    stored_creds["password_salt"] = password_salt
    stored_creds["pbkdf2_iterations"] = PBKDF2_ITERATIONS
    stored_creds["hash_algorithm"] = "pbkdf2_sha256"
    _save_stored_credentials(stored_creds)


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
    if stored_creds.get("username") != username:
        return False

    if _is_pbkdf2_record(stored_creds):
        return _verify_pbkdf2_password(stored_creds, password)

    # Legacy fallback: verify old SHA256 and migrate on success.
    is_valid_legacy = secrets.compare_digest(
        stored_creds.get("password_hash", ""), hash_password(password)
    )
    if is_valid_legacy:
        _upgrade_legacy_password_hash(stored_creds, password)
    return is_valid_legacy


def verify_recovery_code(recovery_code: str) -> bool:
    """Verify recovery code against stored hash."""
    if not recovery_code:
        return False

    stored_creds = _credential_manager.get_stored_credentials()
    expected = stored_creds.get("recovery_code_hash")
    if not expected:
        return False

    return secrets.compare_digest(expected, hash_recovery_code(recovery_code.strip()))


def rotate_credentials(new_password: str | None = None) -> dict[str, Any]:
    """Rotate credentials and return one-time plaintext password and recovery code."""
    stored_creds = load_or_create_credentials()

    if new_password is not None and len(new_password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")

    password = new_password if new_password else secrets.token_urlsafe(16)
    recovery_code = generate_recovery_code()
    password_hash, password_salt = hash_password_secure(password)

    rotated = {
        "username": stored_creds.get("username"),
        "password_hash": password_hash,
        "password_salt": password_salt,
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "hash_algorithm": "pbkdf2_sha256",
        "recovery_code_hash": hash_recovery_code(recovery_code),
        "created_at": datetime.now(UTC).isoformat(),
        "installation_id": stored_creds.get("installation_id") or secrets.token_hex(8),
        "stream_token": secrets.token_urlsafe(STREAM_TOKEN_BYTES),
    }

    _save_stored_credentials(rotated)
    _write_recovery_code_file(recovery_code)

    _credential_manager.cache_plaintext_secrets(password=password, recovery_code=recovery_code)
    return dict(rotated)


def get_recovery_file_path() -> str:
    """Return path to on-disk recovery code helper file."""
    return str(RECOVERY_FILE)


def get_server_info(request: Request) -> dict[str, Any]:
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
            "created_at": datetime.now(UTC).isoformat(),
            "max_connections": "1",
            "allowed_output_formats": ["m3u8", "ts", "rtmp"],
        },
        "server_info": {
            "url": f"{protocol}://{host}",
            "port": request.url.port or (443 if protocol == "https" else 80),
            "https_port": 443 if protocol == "https" else None,
            "server_protocol": protocol,
            "rtmp_port": 1935,
            "timezone": "UTC",
            "timestamp_now": int(datetime.now(UTC).timestamp()),
            "time_now": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        },
    }


async def xtreme_auth_middleware(
    username: str = Query(None), password: str = Query(None)
) -> dict[str, str]:
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


def generate_short_epg(channels: list[dict[str, Any]]) -> str:
    """
    Generate simplified EPG data for channels.

    Args:
        channels: List of channel dictionaries

    Returns:
        JSON string containing EPG data
    """
    epg_data = {"epg_listings": []}

    now = datetime.now(UTC)
    for channel in channels:
        epg_data["epg_listings"].append(
            {
                "channel_id": channel.get("id", ""),
                "epg_id": channel.get("id", ""),
                "title": "Toonami Aftermath Stream",
                "start": now.isoformat(),
                "end": (now + timedelta(hours=24)).isoformat(),
                "description": f"Now streaming: {channel.get('name', 'Unknown')}",
            }
        )

    return json.dumps(epg_data)


def format_xtreme_m3u(
    channels: list[dict[str, Any]], host: str, username: str, stream_token: str
) -> str:
    """
    Format M3U for Xtreme Codes API format.

    Args:
        channels: List of channel dictionaries
        host: Server hostname
        username: Xtreme Codes username
        stream_token: Xtreme stream access token

    Returns:
        M3U formatted string
    """
    lines = ["#EXTM3U"]

    for channel in channels:
        ch_id = channel.get("id", "")
        ch_num = channel.get("number", "")
        ch_name = channel.get("name", "")

        stream_url = f"http://{host}/live/{username}/{stream_token}/{ch_id}.ts"

        extinf = (
            f'#EXTINF:-1 tvg-id="{ch_id}" tvg-name="{ch_name}" '
            f'tvg-logo="" group-title="Toonami"'
        )
        if ch_num:
            extinf += f' tvg-chno="{ch_num}"'
        extinf += f",{ch_name}"

        lines.append(extinf)
        lines.append(stream_url)

    return "\n".join(lines)
