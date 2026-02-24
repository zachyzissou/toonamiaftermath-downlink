import asyncio
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.responses import Response as StarletteResponse

from .xtreme_codes import (
    _credential_manager,
    format_xtreme_m3u,
    generate_short_epg,
    get_recovery_file_path,
    get_server_info,
    load_or_create_credentials,
    rotate_credentials,
    verify_credentials,
    verify_recovery_code,
)


class CachedStaticFiles(StaticFiles):
    """Static files with cache headers for better performance."""

    def file_response(self, full_path: Path, *args: Any, **kwargs: Any) -> StarletteResponse:
        response = super().file_response(full_path, *args, **kwargs)

        path_str = str(full_path)
        if path_str.endswith((".svg", ".png", ".jpg", ".jpeg", ".ico")):
            max_age = 86400  # 1 day for images
        elif path_str.endswith((".css", ".js")):
            max_age = 3600  # 1 hour for CSS/JS (may change during development)
        else:
            max_age = 3600  # 1 hour default

        response.headers["Cache-Control"] = f"public, max-age={max_age}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


# Application constants
DEFAULT_CRON_SCHEDULE = "0 3 * * *"
DEFAULT_PORT = 7004
MAX_CHANNELS_TO_LOG = 100

# Configuration constants
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
PORT = int(os.environ.get("PORT", DEFAULT_PORT))
CRON_SCHEDULE = os.environ.get("CRON_SCHEDULE", DEFAULT_CRON_SCHEDULE)
# Resolve CLI path: default to bundled binary, allow env override
CLI_BIN: Path = Path(os.environ.get("CLI_BIN", "/usr/local/bin/toonamiaftermath-cli"))

# Security constants
MAX_STREAM_CODE_LENGTH = 50
VALID_STREAM_CODE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
APP_ENV = os.environ.get("ENV", "prod").strip().lower()
ALLOWED_ORIGINS = (
    os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if os.environ.get("ALLOWED_ORIGINS")
    else []
)
APP_REFRESH_RATE_LIMIT_SECONDS = int(os.environ.get("APP_REFRESH_RATE_LIMIT_SECONDS", "5"))
APP_REFRESH_TOKEN = os.environ.get("APP_REFRESH_TOKEN", "").strip()
ALLOW_ANONYMOUS_LOCAL_REFRESH = os.environ.get(
    "ALLOW_ANONYMOUS_LOCAL_REFRESH", ""
).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# MIME type constants
MIME_M3U = "application/x-mpegURL"
MIME_XML = "application/xml"

# Error messages
MSG_INVALID_CREDENTIALS = "Invalid credentials"
MSG_M3U_NOT_FOUND = "M3U not yet generated"
MSG_XML_NOT_FOUND = "XML not yet generated"
MSG_ROTATE_AUTH_REQUIRED = "Provide valid credentials or recovery_code"

# File paths
M3U_PATH = DATA_DIR / "index.m3u"
XML_PATH = DATA_DIR / "index.xml"
STATE_PATH = DATA_DIR / "state.json"


class CredentialsRotateRequest(BaseModel):
    """Request body for rotating Xtreme credentials."""

    username: str | None = Field(default=None, max_length=100)
    password: str | None = Field(default=None, max_length=500)
    recovery_code: str | None = Field(default=None, max_length=200)
    new_password: str | None = Field(default=None, min_length=8, max_length=500)


def sanitize_user_input(input_str: str, max_length: int = 100) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not input_str:
        return ""

    sanitized = input_str.strip()[:max_length]

    # Remove potentially dangerous shell/HTML characters.
    dangerous_chars = ["<", ">", "&", '"', "'", ";", "|", "`"]
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    return sanitized


def validate_credentials(username: str, password: str) -> tuple[str, str]:
    """Validate credential inputs."""
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    if len(username) > 100 or len(password) > 500:
        raise HTTPException(status_code=400, detail="Credentials too long")

    return sanitize_user_input(username.strip()), password.strip()


app = FastAPI(title="Toonami Aftermath: Downlink")

# Configure CORS more securely
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
else:
    # Development mode - allow localhost origins only if explicitly allowed
    app.add_middleware(
        CORSMiddleware,
        allow_origins=(
            [
                "http://localhost",
                "http://127.0.0.1",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]
            if APP_ENV in {"dev", "development", "local"}
            else []
        ),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

# Add compression middleware for better performance
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Mount Web UI
WEB_DIR = Path(os.environ.get("WEB_DIR", "/web")).resolve()


# Only mount static files if the directory exists
def setup_web_routes():
    """Setup web UI routes and static file serving."""
    # Ensure correct MIME types for common static assets (especially SVG)
    try:
        mimetypes.add_type("image/svg+xml", ".svg")
        mimetypes.add_type("image/svg+xml", ".svgz")
        mimetypes.add_type("text/css", ".css")
        mimetypes.add_type("application/javascript", ".js")
    except (AttributeError, OSError, ValueError) as exc:
        logger.debug("Could not register MIME types: %s", exc)

    if (WEB_DIR / "assets").exists():
        app.mount(
            "/assets",
            CachedStaticFiles(directory=str(WEB_DIR / "assets")),
            name="assets",
        )

    @app.get("/")
    def web_index():
        """Serve the main web UI or API info."""
        if (WEB_DIR / "index.html").exists():
            response = FileResponse(str(WEB_DIR / "index.html"))
            # Add basic cache headers for HTML (shorter cache for dynamic content)
            response.headers["Cache-Control"] = "public, max-age=300"  # 5 minutes
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        return {"message": "Toonami Aftermath: Downlink API", "docs": "/docs"}


# Setup web routes if in proper environment
if (WEB_DIR / "assets").exists():
    setup_web_routes()
else:

    @app.get("/")
    def api_index():
        return {"message": "Toonami Aftermath: Downlink API", "docs": "/docs"}


# Structured logging configuration
def setup_logging() -> logging.Logger:
    """Setup structured logging with proper levels and formatting."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

    # Simple format that doesn't require extra fields
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logger = logging.getLogger("downlink")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    return logger


# Initialize structured logging
logger = setup_logging()


def _parse_bool_env(value: str | None, default: bool = False) -> bool:
    """Parse common truthy/falsey string values."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Serialize generation to prevent overlapping CLI runs.
_generation_lock = asyncio.Lock()


def _generation_in_progress() -> bool:
    """Return whether a generation task or lock is currently active."""
    task = getattr(app.state, "generation_task", None)
    if task is not None and hasattr(task, "done") and not task.done():
        return True
    return _generation_lock.locked()


async def _run_generate_files_serialized() -> dict[str, Any]:
    """Run generation while preventing concurrent CLI invocations."""
    async with _generation_lock:
        return await generate_files()


def _is_local_host(host: str | None) -> bool:
    """Return True when client host is local."""
    if not host:
        return False
    return host.startswith(("127.", "::1", "localhost"))


def _extract_bearer_token(authorization: str | None) -> str | None:
    """Extract bearer token value from an Authorization header."""
    if not authorization:
        return None
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return authorization


def _is_refresh_request_allowed(
    request: Request,
    x_admin_token: str | None = None,
    authorization: str | None = None,
) -> bool:
    """Validate /refresh request authorization."""
    if ALLOW_ANONYMOUS_LOCAL_REFRESH and _is_local_host(
        request.client.host if request.client else None
    ):
        return True

    if APP_REFRESH_TOKEN:
        provided_token = x_admin_token or _extract_bearer_token(authorization)
        if not provided_token:
            return False
        return secrets.compare_digest(provided_token, APP_REFRESH_TOKEN)

    return False


def _is_refresh_rate_limited() -> tuple[bool, float]:
    """Return whether refresh is currently rate-limited and remaining delay."""
    now = time.monotonic()
    last_request = getattr(app.state, "last_refresh_request", 0.0)
    elapsed = now - float(last_request)
    if elapsed < APP_REFRESH_RATE_LIMIT_SECONDS:
        return True, APP_REFRESH_RATE_LIMIT_SECONDS - elapsed
    app.state.last_refresh_request = now
    return False, 0.0


def _get_credential_stream_token(creds: dict[str, Any]) -> str:
    """Return the current stream token for a credential record."""
    token = creds.get("stream_token")
    if not token:
        return "[REDACTED_STREAM_TOKEN]"
    return str(token)


def _verify_xtreme_access_token(username: str, token: str | None) -> bool:
    """Verify a stream token or fallback to legacy password for Xtreme endpoints."""
    if not token:
        return False

    try:
        creds = load_or_create_credentials()
    except Exception:
        return False

    if creds.get("username") != username:
        return False

    expected = creds.get("stream_token")
    return secrets.compare_digest(str(expected), token) if expected else False


def read_state() -> dict[str, Any]:
    """Read state from file with proper error handling."""
    if STATE_PATH.exists():
        try:
            content = STATE_PATH.read_text()
            return json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read state file: {e}")
            return {}
    return {}


def write_state(state: dict[str, Any]) -> None:
    """Write state to file with proper error handling."""
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, indent=2))
        logger.debug("State file updated successfully")
    except Exception as e:
        logger.error(f"Failed to write state file: {e}")


async def run_cmd(cmd: list[str], cwd: str | None = None) -> int:
    """Execute command asynchronously with proper error handling."""
    return await run_cmd_with_timeout(cmd, cwd, NETWORK_TIMEOUT)


def ensure_cli_exists() -> None:
    """Ensure CLI binary exists and is executable, with helpful diagnostics."""
    if not CLI_BIN.exists():
        raise FileNotFoundError(
            f"toonamiaftermath-cli not found at {CLI_BIN}. Set CLI_BIN env to override."
        )

    if not os.access(str(CLI_BIN), os.X_OK):
        raise PermissionError(
            f"toonamiaftermath-cli at {CLI_BIN} is not executable. "
            f"chmod +x it or rebuild image."
        )

    logger.info(f"CLI binary found and executable: {CLI_BIN}")


async def generate_files() -> dict[str, Any]:
    """
    Generate M3U and XMLTV files using the toonamiaftermath-cli.

    Returns:
        Dict containing generation status and metadata

    Raises:
        FileNotFoundError: If CLI binary is not found
        PermissionError: If CLI binary is not executable
        RuntimeError: If file generation fails after all attempts
    """
    ensure_cli_exists()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Generating M3U and XMLTV via toonamiaftermath-cli (%s)", CLI_BIN)
    logger.info(
        "DATA_DIR=%s | WEB_DIR=%s | CRON_SCHEDULE=%s",
        DATA_DIR,
        WEB_DIR,
        os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE),
    )

    # Try multiple invocation strategies to support different CLI versions
    attempts: list[tuple[list[str], str | None]] = [
        ([str(CLI_BIN), "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN), "run", "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN)], str(DATA_DIR)),  # defaults to index.* in cwd
        # some versions require subcommand
        ([str(CLI_BIN), "run"], str(DATA_DIR)),
    ]

    success = False
    for attempt_num, (cmd, cwd) in enumerate(attempts, 1):
        logger.info(f"Attempt {attempt_num}/{len(attempts)}: {' '.join(cmd)}")
        attempt_started_at = time.time()

        try:
            # Use retry mechanism for CLI execution
            async def run_cli(cmd_args: list[str] = cmd, cmd_cwd: str | None = cwd):
                return_code = await run_cmd(cmd_args, cwd=cmd_cwd)
                if return_code != 0:
                    raise RuntimeError(f"CLI returned non-zero exit code: {return_code}")
                return return_code

            await retry_operation(
                run_cli,
                max_retries=2,  # Fewer retries per command variant
                delay=0.5,
                operation_name=f"CLI execution: {cmd[0]}",
            )

        except Exception as e:
            logger.warning("CLI execution failed for '%s': %s", " ".join(cmd), e)
            if "No such file or directory" in str(e):
                logger.warning(
                    "Binary may be missing required libs on Alpine. "
                    "Ensure libc6-compat, gcompat, and libstdc++ are installed "
                    "in the image."
                )
            continue

        # Check if files were generated successfully
        success = _verify_generated_files(generated_after=attempt_started_at)
        if success:
            break
        logger.warning(
            "Artifact validation failed after successful CLI exit; "
            "files were not refreshed for this attempt."
        )

    if not success:
        raise RuntimeError("Failed to generate M3U/XML files after multiple attempts")

    # Update state
    state = read_state()
    state.update(
        {
            "last_update": datetime.now(UTC).isoformat(),
            "cli_version": await get_cli_version(),
        }
    )
    write_state(state)
    logger.info("Files generated successfully")
    return state


def _verify_generated_files(generated_after: float | None = None) -> bool:
    """
    Verify that M3U and XML files were generated successfully.

    Returns:
        bool: True if both files exist and are valid
    """
    def _is_recent_and_non_empty(path: Path, threshold: float | None) -> bool:
        if not path.exists():
            return False
        stat = path.stat()
        if stat.st_size <= 0:
            logger.warning("Generated artifact is empty: %s", path)
            return False
        if threshold is None:
            return True
        # Small tolerance for filesystem timestamp precision.
        if stat.st_mtime + 1 < threshold:
            logger.warning(
                "Artifact %s appears stale (mtime=%s, expected >= %s)",
                path,
                datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                datetime.fromtimestamp(threshold, tz=UTC).isoformat(),
            )
            return False
        return True

    # If explicit paths were provided, validate them directly.
    if _is_recent_and_non_empty(M3U_PATH, generated_after) and _is_recent_and_non_empty(
        XML_PATH, generated_after
    ):
        return True

    # Otherwise, check common defaults in DATA_DIR (and legacy /app)
    default_m3u_candidates = [DATA_DIR / "index.m3u", Path("/app/index.m3u")]
    default_xml_candidates = [DATA_DIR / "index.xml", Path("/app/index.xml")]

    for dm in default_m3u_candidates:
        if dm.exists() and dm != M3U_PATH:
            try:
                shutil.move(str(dm), str(M3U_PATH))
                logger.info(f"Moved M3U file from {dm} to {M3U_PATH}")
            except Exception as e:
                logger.warning(f"Failed to move M3U file: {e}")
                try:
                    shutil.copyfile(str(dm), str(M3U_PATH))
                    logger.info(f"Copied M3U file from {dm} to {M3U_PATH}")
                except Exception as copy_e:
                    logger.error(f"Failed to copy M3U file: {copy_e}")

    for dx in default_xml_candidates:
        if dx.exists() and dx != XML_PATH:
            try:
                shutil.move(str(dx), str(XML_PATH))
                logger.info(f"Moved XML file from {dx} to {XML_PATH}")
            except Exception as e:
                logger.warning(f"Failed to move XML file: {e}")
                try:
                    shutil.copyfile(str(dx), str(XML_PATH))
                    logger.info(f"Copied XML file from {dx} to {XML_PATH}")
                except Exception as copy_e:
                    logger.error(f"Failed to copy XML file: {copy_e}")

    return _is_recent_and_non_empty(M3U_PATH, generated_after) and _is_recent_and_non_empty(
        XML_PATH, generated_after
    )


async def get_cli_version() -> str | None:
    """
    Get the version of the toonamiaftermath-cli binary.

    Returns:
        Optional[str]: Version string if available, None otherwise
    """
    try:
        cmd = [str(CLI_BIN), "--version"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()

        if proc.returncode == 0:
            version = out.decode().strip()
            return version if version else None
        logger.warning(f"CLI version check failed with code {proc.returncode}: {err.decode()}")
        return None

    except Exception as e:
        logger.warning(f"Failed to get CLI version: {e}")
        return None


def _parse_extinf(line: str) -> tuple[str | None, str | None, str | None]:
    """Parse EXTINF line from M3U file."""
    try:
        parts = line.split(",", 1)
        attrs = parts[0]
        name = parts[1].strip() if len(parts) > 1 else None

        def get_attr(k: str) -> str | None:
            kq = k + '="'
            i = attrs.find(kq)
            if i == -1:
                return None
            j = attrs.find('"', i + len(kq))
            return attrs[i + len(kq) : j] if j != -1 else None

        chan_id = get_attr("tvg-id") or get_attr("channel-id") or "ta"
        number = get_attr("tvg-chno") or get_attr("channel-number")
        return chan_id, number, name
    except Exception as e:
        logger.warning(f"Failed to parse EXTINF line: {line[:50]}... Error: {e}")
        return None, None, None


# Error handling and retry configuration
NETWORK_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds


async def run_cmd_with_timeout(
    cmd: list[str], cwd: str | None = None, timeout: int = NETWORK_TIMEOUT
) -> int:
    """Run command with timeout and proper error handling."""
    try:
        logger.info(f"Running command: {' '.join(cmd[:3])}... (timeout: {timeout}s)")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode != 0:
                logger.warning(
                    f"Command failed with code {proc.returncode}: {stderr.decode()[:200]}"
                )
            else:
                logger.debug(f"Command succeeded: {stdout.decode()[:100]}")

            return proc.returncode

        except TimeoutError:
            logger.error(f"Command timed out after {timeout}s, terminating process")
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                logger.error("Force killing timed out process")
                proc.kill()
                await proc.wait()
            raise RuntimeError(f"Command timed out after {timeout}s") from None

    except FileNotFoundError as e:
        logger.error(f"Command not found: {cmd[0]} - {e}")
        raise RuntimeError(f"Command not found: {cmd[0]}") from e
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise RuntimeError(f"Command execution failed: {e}") from e


async def retry_operation(
    operation_func: Callable[[], Awaitable[Any]],
    max_retries: int = MAX_RETRIES,
    delay: float = RETRY_DELAY,
    operation_name: str = "operation",
) -> Any:
    """Retry an operation with exponential backoff."""
    if max_retries < 1:
        raise ValueError("max_retries must be >= 1")

    last_exception: Exception | None = None

    for attempt in range(max_retries):
        try:
            logger.debug(f"Attempting {operation_name} (attempt {attempt + 1}/{max_retries})")
            return await operation_func()
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                wait_time = delay * (2**attempt)  # Exponential backoff
                logger.warning(
                    f"{operation_name} failed (attempt {attempt + 1}), "
                    f"retrying in {wait_time}s: {e}"
                )
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"{operation_name} failed after {max_retries} attempts: {e}")

    if last_exception is None:
        raise RuntimeError(f"{operation_name} failed without a captured exception")
    raise last_exception


# Enhanced input validation
def validate_stream_code(stream_code: str) -> str:
    """Validate and sanitize stream code input with comprehensive checks."""
    if not stream_code:
        raise HTTPException(status_code=400, detail="Stream code cannot be empty")

    # Length validation
    if len(stream_code) > MAX_STREAM_CODE_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Stream code too long (max {MAX_STREAM_CODE_LENGTH} characters)",
        )

    # Character validation - allow alphanumeric, hyphens, and underscores only
    if not VALID_STREAM_CODE_PATTERN.match(stream_code):
        raise HTTPException(
            status_code=400,
            detail="Stream code contains invalid characters (only alphanumeric, hyphens, and underscores allowed)",
        )

    # Additional security checks
    if stream_code.lower() in ["admin", "root", "system", "config", "api", "test"]:
        raise HTTPException(status_code=400, detail="Stream code contains reserved word")

    return stream_code.lower()  # Normalize to lowercase


def validate_hostname(hostname: str) -> str:
    """Validate hostname/IP for security."""
    # Basic hostname validation
    if not hostname or len(hostname) > 253:
        raise HTTPException(status_code=400, detail="Invalid hostname")

    # Prevent localhost/internal network access in production
    if (
        hostname.lower() in ["localhost", "127.0.0.1", "::1"]
        and os.environ.get("ENV", "dev") == "prod"
    ):
        raise HTTPException(status_code=400, detail="Localhost access not allowed")

    return hostname


# Simple cache for channel data to avoid re-parsing M3U on every request
_channel_cache = {"data": None, "timestamp": None, "file_mtime": None}
CACHE_TTL_SECONDS = 60  # Cache for 1 minute


def parse_channels_from_m3u() -> list[dict[str, Any]]:
    """Parse channel information from M3U file with caching."""
    if not M3U_PATH.exists():
        logger.warning("M3U file does not exist, returning empty channel list")
        return []

    channels: list[dict[str, Any]] = []
    current_time = datetime.now(UTC).timestamp()
    file_mtime: float | None = None

    try:
        file_mtime = M3U_PATH.stat().st_mtime
        # Check if we can use cached data
        if (
            _channel_cache["data"] is not None
            and _channel_cache["timestamp"] is not None
            and _channel_cache["file_mtime"] == file_mtime
            and current_time - _channel_cache["timestamp"] < CACHE_TTL_SECONDS
        ):
            return _channel_cache["data"]

        # Cache miss - parse the file
        pending: dict[str, Any] | None = None
        content = M3U_PATH.read_text(errors="ignore")

        for line_num, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line:
                continue

            if line.startswith("#EXTINF"):
                chan_id, number, name = _parse_extinf(line)
                if name:  # Only create entry if we got a valid name
                    pending = {"id": chan_id, "number": number, "name": name}

            elif not line.startswith("#") and pending and pending.get("name"):
                # Validate URL format
                if line.startswith(("http://", "https://", "rtmp://")):
                    pending["url"] = line
                    channels.append(pending)
                else:
                    logger.warning(f"Invalid URL format at line {line_num}: {line[:50]}...")
                pending = None

    except Exception as e:
        logger.error(f"Failed parsing M3U: {e}")
        return _channel_cache["data"] if _channel_cache["data"] is not None else []

    logger.info(f"Parsed {len(channels)} channels from M3U")

    # Update cache
    _channel_cache["data"] = channels
    _channel_cache["timestamp"] = current_time
    _channel_cache["file_mtime"] = file_mtime

    return channels


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration and monitoring."""
    try:
        # Check basic functionality
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "checks": {
                "api": "ok",
                "data_dir": "ok" if DATA_DIR.exists() else "error",
                "web_assets": "ok" if (WEB_DIR / "assets").exists() else "warning",
                "cli_binary": "ok" if CLI_BIN.exists() else "error",
                "memory": "ok",  # Could add actual memory check
            },
        }

        # Check if any critical services are down
        critical_failures = [
            k
            for k, v in health_status["checks"].items()
            if v == "error" and k in ["data_dir", "cli_binary"]
        ]

        if critical_failures:
            health_status["status"] = "unhealthy"
            return JSONResponse(health_status, status_code=503)

        # Check for warnings
        warnings = [k for k, v in health_status["checks"].items() if v == "warning"]
        if warnings:
            health_status["status"] = "degraded"

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            {
                "status": "unhealthy",
                "timestamp": datetime.now(UTC).isoformat(),
                "error": str(e),
            },
            status_code=503,
        )


@app.get("/status")
async def status():
    """Get application status including last update, next run, and channel count."""
    state = read_state()
    last_update = state.get("last_update")
    cron = os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE)
    cli_version = state.get("cli_version")
    return {
        "last_update": last_update,
        "next_run": (
            app.state.scheduler_next_run if hasattr(app.state, "scheduler_next_run") else None
        ),
        "cron": cron,
        "cli_version": cli_version,
        "channel_count": len(parse_channels_from_m3u()),
        "stream_endpoints_available": True,
    }


@app.get("/m3u")
async def get_m3u():
    """Get the M3U playlist file without stream codes."""
    if not M3U_PATH.exists():
        raise HTTPException(status_code=404, detail=MSG_M3U_NOT_FOUND)

    try:
        return Response(M3U_PATH.read_bytes(), media_type=MIME_M3U)
    except Exception as e:
        logger.error(f"Failed to read M3U file: {e}")
        raise HTTPException(status_code=500, detail="Failed to read M3U file") from e


@app.get("/m3u/stream-codes/{stream_code}")
async def get_m3u_with_stream_code(stream_code: str):
    """M3U playlist with stream codes appended to URLs."""
    # Validate stream code input
    validated_code = validate_stream_code(stream_code)

    if not M3U_PATH.exists():
        raise HTTPException(status_code=404, detail=MSG_M3U_NOT_FOUND)

    try:
        content = M3U_PATH.read_text(errors="ignore")
        lines = []
        for original_line in content.splitlines():
            line = original_line
            if line.strip() and not line.startswith("#"):
                # This is a URL line, add stream code
                if "?" in line:
                    line = f"{line}&code={validated_code}"
                else:
                    line = f"{line}?code={validated_code}"
            lines.append(line)
        return Response("\n".join(lines), media_type=MIME_M3U)
    except Exception as e:
        logger.error(f"Failed to process M3U with stream code: {e}")
        raise HTTPException(status_code=500, detail="Failed to process M3U file") from e


@app.get("/xml")
async def get_xml():
    if not XML_PATH.exists():
        raise HTTPException(status_code=404, detail="XML not yet generated")
    return Response(XML_PATH.read_bytes(), media_type=MIME_XML)


@app.get("/channels")
async def channels():
    return parse_channels_from_m3u()


@app.post("/refresh")
async def refresh(
    request: Request,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    authorization: str | None = Header(default=None),
):
    if not _is_refresh_request_allowed(
        request, x_admin_token=x_admin_token, authorization=authorization
    ):
        raise HTTPException(status_code=401, detail="Unauthorized refresh request")

    throttled, wait_seconds = _is_refresh_rate_limited()
    if throttled:
        raise HTTPException(
            status_code=429,
            detail=f"Refresh in progress or rate-limited. Retry in {int(wait_seconds)}s.",
        )

    if _generation_in_progress():
        raise HTTPException(status_code=429, detail="Generation already in progress")

    task = asyncio.create_task(_run_generate_files_serialized())

    def _refresh_completion(task_result: asyncio.Task[dict[str, Any]]) -> None:
        if task_result.cancelled():
            logger.info("Manual refresh task cancelled")
            return
        exc = task_result.exception()
        if exc:
            logger.error("Manual refresh task failed: %s", exc)
            return
        logger.info("Manual refresh task completed successfully")

    task.add_done_callback(_refresh_completion)
    app.state.last_refresh_task = task
    return {"ok": True}


# Xtreme Codes API endpoints
@app.get("/player_api.php")
async def xtreme_player_api(
    request: Request,
    username: str = Query(None),
    password: str = Query(None),
    action: str = Query(None),
):
    """Xtreme Codes API endpoint."""
    # Validate and verify credentials
    if not username or not password:
        logger.warning(
            f"Authentication attempt without credentials from {request.client.host}"
        )
        return JSONResponse({"user_info": {"auth": 0}}, status_code=401)

    try:
        username, password = validate_credentials(username, password)
        if not verify_credentials(username, password):
            logger.warning(
                "Invalid credentials attempt from %s for user %s",
                request.client.host,
                username,
            )
            return JSONResponse({"user_info": {"auth": 0}}, status_code=401)
    except HTTPException as e:
        logger.warning(f"Credential validation failed from {request.client.host}: {e.detail}")
        return JSONResponse({"user_info": {"auth": 0}}, status_code=401)

    request.state.username = username
    request.state.password = password
    logger.info(f"Successful authentication for user {username}")

    if action == "get_live_categories":
        return JSONResponse([{"category_id": "1", "category_name": "Toonami", "parent_id": 0}])

    if action == "get_live_streams":
        channels = parse_channels_from_m3u()
        streams = []
        for i, ch in enumerate(channels):
            streams.append(
                {
                    "num": i + 1,
                    "name": ch.get("name", ""),
                    "stream_type": "live",
                    "stream_id": ch.get("id", str(i)),
                    "stream_icon": "",
                    "epg_channel_id": ch.get("id", ""),
                    "added": datetime.now(UTC).isoformat(),
                    "category_id": "1",
                    "custom_sid": ch.get("id", ""),
                    "tv_archive": 0,
                    "direct_source": ch.get("url", ""),
                    "tv_archive_duration": 0,
                }
            )
        return JSONResponse(streams)

    if action == "get_simple_data_table":
        channels = parse_channels_from_m3u()
        return PlainTextResponse(generate_short_epg(channels))

    # Default: return server info
    return JSONResponse(get_server_info(request))


@app.get("/get.php")
async def xtreme_get(
    request: Request,
    username: str = Query(None),
    password: str = Query(None),
    token: str = Query(None),
    type_param: str = Query("m3u_plus", alias="type"),
    output_param: str = Query("ts", alias="output"),
):
    """Xtreme Codes get.php endpoint for M3U."""
    try:
        normalized_username = sanitize_user_input(username or "")
        if not normalized_username or len(normalized_username) > 100:
            raise HTTPException(status_code=400, detail="Username required")
        username = normalized_username
    except HTTPException as e:
        logger.warning(f"M3U request validation failed from {request.client.host}: {e.detail}")
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)

    token_auth_ok = _verify_xtreme_access_token(username, token)
    if not token_auth_ok:
        try:
            username, password = validate_credentials(username, password)
            if not verify_credentials(username, password):
                raise HTTPException(status_code=401, detail="Invalid credentials")
        except HTTPException as e:
            logger.warning(
                f"M3U request validation failed from {request.client.host}: {e.detail}"
            )
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)

    channels = parse_channels_from_m3u()
    host = request.headers.get("host", "localhost")
    stream_token = load_or_create_credentials().get("stream_token")
    if not stream_token:
        raise HTTPException(status_code=500, detail="Stream token unavailable")

    m3u_content = format_xtreme_m3u(channels, host, username, stream_token)
    return Response(m3u_content, media_type=MIME_M3U)


@app.get("/xmltv.php")
async def xtreme_xmltv(
    request: Request,
    username: str = Query(None),
    password: str = Query(None),
    token: str = Query(None),
):
    """Xtreme Codes XMLTV endpoint."""
    if not _verify_xtreme_access_token(username or "", token):
        try:
            username, password = validate_credentials(username, password)
            if not verify_credentials(username, password):
                logger.warning(
                    f"Invalid credentials for XMLTV request from {request.client.host}"
                )
                return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
        except HTTPException as e:
            logger.warning(
                f"XMLTV request validation failed from {request.client.host}: {e.detail}"
            )
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)

    if not XML_PATH.exists():
        raise HTTPException(status_code=404, detail="XML not yet generated")

    return Response(XML_PATH.read_bytes(), media_type=MIME_XML)


@app.get("/live/{username}/{password}/{stream_id}.{ext}")
async def xtreme_stream(
    request: Request, username: str, password: str, stream_id: str, ext: str
):
    """Xtreme Codes live stream redirect."""
    if not _verify_xtreme_access_token(username, password):
        try:
            username, password = validate_credentials(username, password)
            if not verify_credentials(username, password):
                logger.warning(
                    f"Invalid credentials for stream {stream_id} from {request.client.host}"
                )
                return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
        except HTTPException as e:
            logger.warning(
                f"Stream request validation failed from {request.client.host}: {e.detail}"
            )
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)

    # Find the actual stream URL
    channels = parse_channels_from_m3u()
    for ch in channels:
        if ch.get("id") == stream_id or str(ch.get("id", "")).replace(".", "_") == stream_id:
            stream_url = ch.get("url", "")
            if stream_url:
                logger.info(f"Stream redirect for {stream_id} to user {username}")
                return RedirectResponse(url=stream_url, status_code=302)

    logger.warning(f"Stream {stream_id} not found for user {username}")
    raise HTTPException(status_code=404, detail="Stream not found")


@app.get("/credentials")
async def get_credentials(request: Request):
    """Get Xtreme Codes credentials for this installation."""
    creds = load_or_create_credentials()
    host = request.headers.get("host", "localhost:7004")
    protocol = "https" if request.url.scheme == "https" else "http"

    display_password = _credential_manager.pop_password_for_display()
    display_recovery_code = _credential_manager.pop_recovery_code_for_display()
    password_available = bool(display_password)
    recovery_code_available = bool(display_recovery_code)
    stream_token = _get_credential_stream_token(creds)

    return {
        "username": creds.get("username"),
        "password": display_password,
        "password_available": password_available,
        "recovery_code": display_recovery_code,
        "recovery_code_available": recovery_code_available,
        "created_at": creds.get("created_at"),
        "installation_id": creds.get("installation_id"),
        "server_url": host,
        "instructions": (
            "Use these credentials in your IPTV player's Xtreme Codes API settings. "
            "If password is unavailable, rotate credentials via POST /credentials/rotate."
        ),
        "security_note": (
            "Password and recovery code are shown once. A recovery file is stored on disk "
            "for secure rotation."
        ),
        "recovery": {
            "file_path": Path(get_recovery_file_path()).name,
            "rotate_endpoint": "/credentials/rotate",
        },
        "setup_guide": {
            "tivimate": "Add M3U Playlist → Xtreme Codes → Enter server, username, password",
            "iptv_smarters": (
                "Add Playlist → Xtreme Codes → Enter server URL, username, password"
            ),
            "perfect_player": "Settings → Playlist → Add → Xtreme Codes → Enter details",
        },
        "direct_urls": {
            "standard_m3u": f"{protocol}://{host}/m3u",
            "standard_xml": f"{protocol}://{host}/xml",
            "xtreme_m3u": (
                f"{protocol}://{host}/get.php?username={creds.get('username')}"
                f"&token={stream_token}"
            ),
            "xtreme_xml": (
                f"{protocol}://{host}/xmltv.php?username={creds.get('username')}"
                f"&token={stream_token}"
            ),
        },
    }


@app.post("/credentials/rotate")
async def rotate_xtreme_credentials(request: Request, payload: CredentialsRotateRequest):
    """
    Rotate Xtreme credentials.

    Authorization options:
    1) Existing username/password pair
    2) Recovery code from DATA_DIR/credentials.recovery
    """
    authorized = False

    if payload.username and payload.password:
        try:
            username, password = validate_credentials(payload.username, payload.password)
            authorized = verify_credentials(username, password)
        except HTTPException:
            authorized = False

    if not authorized and payload.recovery_code:
        authorized = verify_recovery_code(payload.recovery_code)

    if not authorized:
        raise HTTPException(status_code=401, detail=MSG_ROTATE_AUTH_REQUIRED)

    try:
        rotated = rotate_credentials(payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    host = request.headers.get("host", "localhost:7004")
    protocol = "https" if request.url.scheme == "https" else "http"

    response_password = _credential_manager.pop_password_for_display()
    response_recovery_code = _credential_manager.pop_recovery_code_for_display()

    return {
        "username": rotated.get("username"),
        "password": response_password,
        "recovery_code": response_recovery_code,
        "created_at": rotated.get("created_at"),
        "installation_id": rotated.get("installation_id"),
        "server_url": host,
        "recovery_file": Path(get_recovery_file_path()).name,
        "direct_urls": {
            "xtreme_m3u": (
                f"{protocol}://{host}/get.php?username={rotated.get('username')}"
                f"&token={rotated.get('stream_token')}"
            ),
            "xtreme_xml": (
                f"{protocol}://{host}/xmltv.php?username={rotated.get('username')}"
                f"&token={rotated.get('stream_token')}"
            ),
        },
    }


@app.get("/stream-codes")
async def get_stream_codes(request: Request):
    """Get ready-to-use stream code URLs with credentials pre-filled."""
    creds = load_or_create_credentials()
    display_password = _credential_manager.get_password_for_display()
    password_available = bool(display_password)
    host = request.headers.get("host", "localhost:7004")
    protocol = "https" if request.url.scheme == "https" else "http"

    # Generate some common stream codes
    stream_codes = ["live", "premium", "hd", "4k", "mobile"]

    urls = {}
    for code in stream_codes:
        urls[code] = f"{protocol}://{host}/m3u/stream-codes/{code}"

    return {
        "stream_code_urls": urls,
        "description": "Ready-to-use M3U URLs with different stream codes appended",
        "credentials": {
            "username": creds.get("username"),
            "password": display_password if password_available else None,
            "password_available": password_available,
        },
        "usage": "Copy any URL above directly into your IPTV player - no credential entry needed!",
    }


# Cron scheduler constants and patterns
CRON_RE = re.compile(
    r"^\s*([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s*$"
)
DEFAULT_FALLBACK_HOUR = 3
MAX_SCHEDULE_SEARCH_MINUTES = 24 * 60 + 2


def parse_cron_field(val: str, default_value: int) -> tuple[str, int | None]:
    """
    Parse a single cron field (minute, hour, etc.).

    Args:
        val: Cron field value (e.g., "*", "5", "*/15")
        default_value: Default value to use for calculations

    Returns:
        Tuple of (field_type, value) where field_type is "any", "fixed", "step", or "invalid"
    """
    if val == "*":
        return "any", None
    if val.startswith("*/") and val[2:].isdigit():
        return "step", int(val[2:])
    if val.isdigit():
        return "fixed", int(val)
    return "invalid", None


def get_fallback_next_run(dt: datetime) -> datetime:
    """
    Get fallback next run time (3 AM next day if past 3 AM, today if before).

    Args:
        dt: Current datetime

    Returns:
        Next fallback run time
    """
    base = dt.replace(hour=DEFAULT_FALLBACK_HOUR, minute=0, second=0, microsecond=0)
    return base if base > dt else base + timedelta(days=1)


def validate_cron_expression(expr: str) -> tuple[str, str, str, str, str] | None:
    """
    Validate and parse cron expression.

    Args:
        expr: Cron expression string

    Returns:
        Tuple of (mins, hrs, dom, mon, dow) if valid, None otherwise
    """
    match = CRON_RE.match(expr)
    if not match:
        logger.warning(f"Invalid cron expression format: {expr}")
        return None
    return match.groups()


def check_time_matches_cron(
    candidate: datetime,
    min_mode: str,
    min_val: int | None,
    hr_mode: str,
    hr_val: int | None,
) -> bool:
    """
    Check if a given time matches the cron schedule.

    Args:
        candidate: Datetime to check
        min_mode: Minute field type ("any", "fixed", "step")
        min_val: Minute value (if applicable)
        hr_mode: Hour field type ("any", "fixed", "step")
        hr_val: Hour value (if applicable)

    Returns:
        bool: True if time matches schedule
    """
    h = candidate.hour
    mnt = candidate.minute

    ok_min = (
        (min_mode == "any")
        or (min_mode == "fixed" and mnt == (min_val or 0))
        or (min_mode == "step" and min_val and (mnt % min_val == 0))
    )

    ok_hr = (
        (hr_mode == "any")
        or (hr_mode == "fixed" and h == (hr_val or 0))
        or (hr_mode == "step" and hr_val and (h % hr_val == 0))
    )

    return ok_min and ok_hr


def cron_next(dt: datetime, expr: str) -> datetime | None:
    """
    Calculate next run time based on cron expression.

    Args:
        dt: Current datetime
        expr: Cron expression (minute hour dom month dow)

    Returns:
        Next scheduled run time, or None if invalid
    """
    # Parse and validate cron expression
    cron_parts = validate_cron_expression(expr)
    if not cron_parts:
        return get_fallback_next_run(dt)

    mins, hrs, dom, mon, dow = cron_parts

    # Parse minute and hour fields (we only support these for now)
    min_mode, min_val = parse_cron_field(mins, 0)
    hr_mode, hr_val = parse_cron_field(hrs, DEFAULT_FALLBACK_HOUR)

    # Check for invalid fields or unsupported complex expressions
    if "invalid" in (min_mode, hr_mode) or any(
        x not in ("*",) and not x.isdigit() for x in (dom, mon, dow)
    ):
        logger.warning(f"Unsupported cron expression: {expr}, using fallback schedule")
        return get_fallback_next_run(dt)

    # Search for next matching time
    candidate = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)

    for _ in range(MAX_SCHEDULE_SEARCH_MINUTES):
        if check_time_matches_cron(candidate, min_mode, min_val, hr_mode, hr_val):
            return candidate
        candidate += timedelta(minutes=1)

    # If no match found in reasonable time, use fallback
    logger.warning(f"No schedule match found for {expr}, using fallback")
    return get_fallback_next_run(dt)


async def scheduler_loop():
    """
    Main scheduler loop that runs file generation on schedule.

    Runs initial generation at startup, then runs according to CRON_SCHEDULE.
    Includes error handling and recovery mechanisms.
    """
    # Initial run at startup
    logger.info("Starting scheduler with initial file generation")
    try:
        await _run_generate_files_serialized()
        logger.info("Initial file generation completed successfully")
    except Exception as e:
        logger.error("Initial generation failed: %s", e)

    # Main scheduling loop
    consecutive_failures = 0
    max_consecutive_failures = 3

    while True:
        try:
            now = datetime.now(UTC)
            cron_expression = os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE)
            next_run = cron_next(now, cron_expression)

            if next_run:
                app.state.scheduler_next_run = next_run.isoformat()
                delay = max(5.0, (next_run - now).total_seconds())
                logger.info("Next scheduled run at %s (in %.0fs)", next_run, delay)
            else:
                # Fallback if cron calculation fails
                delay = 3600  # 1 hour fallback
                app.state.scheduler_next_run = None
                logger.warning("Could not calculate next run time, using 1-hour fallback")

            # Wait for scheduled time
            await asyncio.sleep(delay)

            # Run scheduled generation
            if _generation_in_progress():
                logger.warning(
                    "Scheduled generation skipped: another generation is already running"
                )
                continue

            await _run_generate_files_serialized()
            logger.info("Scheduled file generation completed successfully")
            consecutive_failures = 0  # Reset failure counter on success

        except asyncio.CancelledError:
            logger.info("Scheduler loop cancelled")
            raise
        except Exception as e:
            consecutive_failures += 1
            logger.error(
                "Scheduled generation failed (attempt %d/%d): %s",
                consecutive_failures,
                max_consecutive_failures,
                e,
            )

            if consecutive_failures >= max_consecutive_failures:
                logger.critical("Maximum consecutive failures reached, extending retry delay")
                await asyncio.sleep(300)  # 5 minute delay after multiple failures
            else:
                await asyncio.sleep(30)  # 30 second delay for single failures


@app.on_event("startup")
async def on_startup():
    # Initialize credentials on startup
    creds = load_or_create_credentials()
    app.state.scheduler_task = asyncio.create_task(scheduler_loop())
    logger.info("Xtreme Codes API credentials ready")
    logger.info(f"Username: {creds.get('username')}")
    logger.info(f"Toonami Aftermath: Downlink running on http://localhost:{PORT}")
    logger.info("View full credentials and setup guide in WebUI")

    # Show first-time setup info if this is a new installation
    created_recently = False
    try:
        created_at = datetime.fromisoformat(creds.get("created_at", ""))
        time_since_creation = datetime.now(UTC) - created_at
        created_recently = time_since_creation.total_seconds() < 60  # Created in last minute
    except (TypeError, ValueError) as exc:
        logger.debug("Could not parse credential creation time: %s", exc)

    if created_recently:
        logger.info("Welcome! This appears to be your first launch.")
        logger.info("Your unique IPTV credentials are ready to use.")
        logger.info("No configuration needed - everything works out of the box!")


def create_app():
    """Create and configure the FastAPI application instance."""
    return app
