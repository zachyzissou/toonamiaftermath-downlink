import os
import mimetypes
import json
import shutil
import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, Response, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import (
    FileResponse, RedirectResponse, JSONResponse, PlainTextResponse
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .xtreme_codes import (
    load_or_create_credentials, verify_credentials, get_server_info,
    generate_short_epg, format_xtreme_m3u, _credential_manager,
    rotate_credentials, verify_recovery_code, get_recovery_file_path
)

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
VALID_STREAM_CODE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
ALLOWED_ORIGINS = (
    os.environ.get("ALLOWED_ORIGINS", "").split(",") 
    if os.environ.get("ALLOWED_ORIGINS") 
    else []
)

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
    username: Optional[str] = Field(default=None, max_length=100)
    password: Optional[str] = Field(default=None, max_length=500)
    recovery_code: Optional[str] = Field(default=None, max_length=200)
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=500)

def validate_stream_code(stream_code: str) -> str:
    """Validate and sanitize stream code input."""
    if not stream_code:
        raise HTTPException(status_code=400, detail="Stream code cannot be empty")
    
    if len(stream_code) > MAX_STREAM_CODE_LENGTH:
        raise HTTPException(status_code=400, detail="Stream code too long")
    
    if not VALID_STREAM_CODE_PATTERN.match(stream_code):
        raise HTTPException(status_code=400, detail="Invalid stream code format")
    
    return stream_code

def validate_credentials(username: str, password: str) -> tuple[str, str]:
    """Validate credential inputs."""
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    if len(username) > 100 or len(password) > 500:
        raise HTTPException(status_code=400, detail="Credentials too long")
    
    return username.strip(), password.strip()

app = FastAPI(title="Toonami Aftermath: Downlink")

# Configure CORS more securely
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"]
    )
else:
    # Development mode - allow localhost origins only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"]
    )

# Mount Web UI
WEB_DIR = Path(os.environ.get("WEB_DIR", "/web")).resolve()

# Only mount static files if the directory exists
def setup_web_routes():
    """Setup web UI routes and static file serving."""
    # Ensure correct MIME types for common static assets (especially SVG)
    try:
        mimetypes.add_type('image/svg+xml', '.svg')
        mimetypes.add_type('image/svg+xml', '.svgz')
        mimetypes.add_type('text/css', '.css')
        mimetypes.add_type('application/javascript', '.js')
    except Exception:
        pass

    if (WEB_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")
    
    @app.get("/")
    def web_index():
        """Serve the main web UI or API info."""
        if (WEB_DIR / "index.html").exists():
            return FileResponse(str(WEB_DIR / "index.html"))
        else:
            return {"message": "Toonami Aftermath: Downlink API", "docs": "/docs"}

# Setup web routes if in proper environment
if (WEB_DIR / "assets").exists():
    setup_web_routes()
else:
    @app.get("/")
    def api_index():
        return {"message": "Toonami Aftermath: Downlink API", "docs": "/docs"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("downlink")


def read_state() -> Dict[str, Any]:
    """Read state from file with proper error handling."""
    if STATE_PATH.exists():
        try:
            content = STATE_PATH.read_text()
            return json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read state file: {e}")
            return {}
    return {}


def write_state(state: Dict[str, Any]) -> None:
    """Write state to file with proper error handling."""
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, indent=2))
        logger.debug("State file updated successfully")
    except Exception as e:
        logger.error(f"Failed to write state file: {e}")


async def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> int:
    """Execute command asynchronously with proper error handling."""
    logger.info("Executing: %s%s", " ".join(cmd), f" (cwd={cwd})" if cwd else "")
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd
        )
        
        if not proc.stdout:
            logger.error("Failed to capture command output")
            return -1
            
        async for line in proc.stdout:
            decoded_line = line.decode(errors="ignore").rstrip()
            if decoded_line:  # Only log non-empty lines
                logger.info(decoded_line)
                
        return_code = await proc.wait()
        logger.info(f"Command completed with return code: {return_code}")
        return return_code
        
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return -1


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


async def generate_files() -> Dict[str, Any]:
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
        DATA_DIR, WEB_DIR, os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE)
    )

    # Try multiple invocation strategies to support different CLI versions
    attempts: List[Tuple[List[str], Optional[str]]] = [
        ([str(CLI_BIN), "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN), "run", "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN)], str(DATA_DIR)),                   # defaults to index.* in cwd
        ([str(CLI_BIN), "run"], str(DATA_DIR)),          # some versions require subcommand
    ]

    success = False
    for attempt_num, (cmd, cwd) in enumerate(attempts, 1):
        logger.info(f"Attempt {attempt_num}/{len(attempts)}: {' '.join(cmd)}")
        
        try:
            return_code = await run_cmd(cmd, cwd=cwd)
            if return_code != 0:
                logger.warning(f"CLI returned non-zero exit code: {return_code}")
                continue
                
        except Exception as e:
            logger.warning("CLI execution failed for '%s': %s", " ".join(cmd), e)
            if "No such file or directory" in str(e):
                logger.warning(
                    "Binary may be missing required libs on Alpine. "
                    "Ensure libc6-compat, gcompat, and libstdc++ are installed in the image."
                )
            continue

        # Check if files were generated successfully
        success = _verify_generated_files()
        if success:
            break

    if not success:
        raise RuntimeError("Failed to generate M3U/XML files after multiple attempts")

    # Update state
    state = read_state()
    state.update({
        "last_update": datetime.now(timezone.utc).isoformat(),
        "cli_version": await get_cli_version(),
    })
    write_state(state)
    logger.info("Files generated successfully")
    return state


def _verify_generated_files() -> bool:
    """
    Verify that M3U and XML files were generated successfully.
    
    Returns:
        bool: True if both files exist and are valid
    """
    # If explicit paths were provided, check them directly
    if M3U_PATH.exists() and XML_PATH.exists():
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

    return M3U_PATH.exists() and XML_PATH.exists()


async def get_cli_version() -> Optional[str]:
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
        else:
            logger.warning(f"CLI version check failed with code {proc.returncode}: {err.decode()}")
            return None
            
    except Exception as e:
        logger.warning(f"Failed to get CLI version: {e}")
        return None


def _parse_extinf(line: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse EXTINF line from M3U file."""
    try:
        parts = line.split(",", 1)
        attrs = parts[0]
        name = parts[1].strip() if len(parts) > 1 else None
        
        def get_attr(k: str) -> Optional[str]:
            kq = k + "=\""
            i = attrs.find(kq)
            if i == -1:
                return None
            j = attrs.find("\"", i + len(kq))
            return attrs[i+len(kq):j] if j != -1 else None
        
        chan_id = get_attr("tvg-id") or get_attr("channel-id") or "ta"
        number = get_attr("tvg-chno") or get_attr("channel-number")
        return chan_id, number, name
    except Exception as e:
        logger.warning(f"Failed to parse EXTINF line: {line[:50]}... Error: {e}")
        return None, None, None


def parse_channels_from_m3u() -> List[Dict[str, Any]]:
    """Parse channel information from M3U file."""
    channels: List[Dict[str, Any]] = []
    if not M3U_PATH.exists():
        logger.warning("M3U file does not exist, returning empty channel list")
        return channels
    
    try:
        pending: Optional[Dict[str, Any]] = None
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
                if line.startswith(('http://', 'https://', 'rtmp://')):
                    pending["url"] = line
                    channels.append(pending)
                else:
                    logger.warning(f"Invalid URL format at line {line_num}: {line[:50]}...")
                pending = None
                
    except Exception as e:
        logger.error(f"Failed parsing M3U: {e}")
        
    logger.info(f"Parsed {len(channels)} channels from M3U")
    return channels


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
            app.state.scheduler_next_run 
            if hasattr(app.state, 'scheduler_next_run') 
            else None
        ),
        "cron": cron,
        "cli_version": cli_version,
        "channel_count": len(parse_channels_from_m3u()),
        "stream_endpoints_available": True
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
        raise HTTPException(status_code=500, detail="Failed to read M3U file")


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
        for line in content.splitlines():
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
        raise HTTPException(status_code=500, detail="Failed to process M3U file")


@app.get("/xml")
async def get_xml():
    if not XML_PATH.exists():
        raise HTTPException(status_code=404, detail="XML not yet generated")
    return Response(XML_PATH.read_bytes(), media_type=MIME_XML)


@app.get("/channels")
async def channels():
    return parse_channels_from_m3u()


@app.post("/refresh")
async def refresh():
    task = asyncio.create_task(generate_files())
    app.state.last_refresh_task = task
    return {"ok": True}


# Xtreme Codes API endpoints
@app.get("/player_api.php")
async def xtreme_player_api(
    request: Request,
    username: str = Query(None),
    password: str = Query(None),
    action: str = Query(None)
):
    """Xtreme Codes API endpoint."""
    # Validate and verify credentials
    if not username or not password:
        logger.warning(f"Authentication attempt without credentials from {request.client.host}")
        return JSONResponse({"user_info": {"auth": 0}}, status_code=401)
    
    try:
        username, password = validate_credentials(username, password)
        if not verify_credentials(username, password):
            logger.warning(
                f"Invalid credentials attempt from {request.client.host} for user {username}"
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
    
    elif action == "get_live_streams":
        channels = parse_channels_from_m3u()
        streams = []
        for i, ch in enumerate(channels):
            streams.append({
                "num": i + 1,
                "name": ch.get("name", ""),
                "stream_type": "live",
                "stream_id": ch.get("id", str(i)),
                "stream_icon": "",
                "epg_channel_id": ch.get("id", ""),
                "added": datetime.now(timezone.utc).isoformat(),
                "category_id": "1",
                "custom_sid": ch.get("id", ""),
                "tv_archive": 0,
                "direct_source": ch.get("url", ""),
                "tv_archive_duration": 0
            })
        return JSONResponse(streams)
    
    elif action == "get_simple_data_table":
        channels = parse_channels_from_m3u()
        return PlainTextResponse(generate_short_epg(channels))
    
    else:
        # Default: return server info
        return JSONResponse(get_server_info(request))


@app.get("/get.php")
async def xtreme_get(
    request: Request,
    username: str = Query(None),
    password: str = Query(None),
    type_param: str = Query("m3u_plus", alias="type"),
    output_param: str = Query("ts", alias="output")
):
    """Xtreme Codes get.php endpoint for M3U."""
    try:
        username, password = validate_credentials(username, password)
        if not verify_credentials(username, password):
            logger.warning(f"Invalid credentials for M3U request from {request.client.host}")
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    except HTTPException as e:
        logger.warning(f"M3U request validation failed from {request.client.host}: {e.detail}")
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    
    channels = parse_channels_from_m3u()
    host = request.headers.get("host", "localhost")
    
    m3u_content = format_xtreme_m3u(channels, host, username, password)
    return Response(m3u_content, media_type=MIME_M3U)


@app.get("/xmltv.php")
async def xtreme_xmltv(
    request: Request,
    username: str = Query(None),
    password: str = Query(None)
):
    """Xtreme Codes XMLTV endpoint."""
    try:
        username, password = validate_credentials(username, password)
        if not verify_credentials(username, password):
            logger.warning(f"Invalid credentials for XMLTV request from {request.client.host}")
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    except HTTPException as e:
        logger.warning(f"XMLTV request validation failed from {request.client.host}: {e.detail}")
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    
    if not XML_PATH.exists():
        raise HTTPException(status_code=404, detail="XML not yet generated")
    
    return Response(XML_PATH.read_bytes(), media_type=MIME_XML)


@app.get("/live/{username}/{password}/{stream_id}.{ext}")
async def xtreme_stream(
    request: Request,
    username: str,
    password: str,
    stream_id: str,
    ext: str
):
    """Xtreme Codes live stream redirect."""
    try:
        username, password = validate_credentials(username, password)
        if not verify_credentials(username, password):
            logger.warning(f"Invalid credentials for stream {stream_id} from {request.client.host}")
            return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    except HTTPException as e:
        logger.warning(f"Stream request validation failed from {request.client.host}: {e.detail}")
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
    host = request.headers.get('host', 'localhost:7004')
    protocol = "https" if request.url.scheme == "https" else "http"

    display_password = _credential_manager.get_password_for_display()
    display_recovery_code = _credential_manager.get_recovery_code_for_display()
    password_available = bool(display_password)
    recovery_code_available = bool(display_recovery_code)

    # Clear one-time secrets from memory once presented to caller.
    if password_available:
        _credential_manager.clear_password_cache()
    if recovery_code_available:
        _credential_manager.clear_recovery_code_cache()

    password_for_urls = display_password if password_available else "[PASSWORD]"

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
            "file_path": get_recovery_file_path(),
            "rotate_endpoint": "/credentials/rotate"
        },
        "setup_guide": {
            "tivimate": "Add M3U Playlist → Xtreme Codes → Enter server, username, password",
            "iptv_smarters": "Add Playlist → Xtreme Codes → Enter server URL, username, password", 
            "perfect_player": "Settings → Playlist → Add → Xtreme Codes → Enter details"
        },
        "direct_urls": {
            "standard_m3u": f"{protocol}://{host}/m3u",
            "standard_xml": f"{protocol}://{host}/xml",
            "xtreme_m3u": (
                f"{protocol}://{host}/get.php?username={creds.get('username')}"
                f"&password={password_for_urls}"
            ),
            "xtreme_xml": (
                f"{protocol}://{host}/xmltv.php?username={creds.get('username')}"
                f"&password={password_for_urls}"
            )
        }
    }


@app.post("/credentials/rotate")
async def rotate_xtreme_credentials(
    request: Request,
    payload: CredentialsRotateRequest
):
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
        raise HTTPException(status_code=400, detail=str(e))

    host = request.headers.get('host', 'localhost:7004')
    protocol = "https" if request.url.scheme == "https" else "http"

    # Return one-time secrets immediately after rotation.
    response_password = rotated.get("password")
    response_recovery_code = rotated.get("recovery_code")
    _credential_manager.clear_password_cache()
    _credential_manager.clear_recovery_code_cache()

    return {
        "username": rotated.get("username"),
        "password": response_password,
        "recovery_code": response_recovery_code,
        "created_at": rotated.get("created_at"),
        "installation_id": rotated.get("installation_id"),
        "server_url": host,
        "recovery_file": get_recovery_file_path(),
        "direct_urls": {
            "xtreme_m3u": (
                f"{protocol}://{host}/get.php?username={rotated.get('username')}"
                f"&password={response_password}"
            ),
            "xtreme_xml": (
                f"{protocol}://{host}/xmltv.php?username={rotated.get('username')}"
                f"&password={response_password}"
            )
        }
    }


@app.get("/stream-codes")
async def get_stream_codes(request: Request):
    """Get ready-to-use stream code URLs with credentials pre-filled."""
    creds = load_or_create_credentials()
    host = request.headers.get('host', 'localhost:7004')
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
            "password": creds.get("password")
        },
        "usage": "Copy any URL above directly into your IPTV player - no credential entry needed!"
    }


# Cron scheduler constants and patterns
CRON_RE = re.compile(
    r"^\s*([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s*$"
)
DEFAULT_FALLBACK_HOUR = 3
MAX_SCHEDULE_SEARCH_MINUTES = 24 * 60 + 2

def parse_cron_field(val: str, default_value: int) -> Tuple[str, Optional[int]]:
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

def validate_cron_expression(expr: str) -> Optional[Tuple[str, str, str, str, str]]:
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

def check_time_matches_cron(candidate: datetime, min_mode: str, min_val: Optional[int], 
                          hr_mode: str, hr_val: Optional[int]) -> bool:
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
        (min_mode == "any") or
        (min_mode == "fixed" and mnt == (min_val or 0)) or
        (min_mode == "step" and min_val and (mnt % min_val == 0))
    )
    
    ok_hr = (
        (hr_mode == "any") or
        (hr_mode == "fixed" and h == (hr_val or 0)) or
        (hr_mode == "step" and hr_val and (h % hr_val == 0))
    )
    
    return ok_min and ok_hr

def cron_next(dt: datetime, expr: str) -> Optional[datetime]:
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
        await generate_files()
        logger.info("Initial file generation completed successfully")
    except Exception as e:
        logger.error("Initial generation failed: %s", e)
    
    # Main scheduling loop
    consecutive_failures = 0
    max_consecutive_failures = 3
    
    while True:
        try:
            now = datetime.now(timezone.utc)
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
            await generate_files()
            logger.info("Scheduled file generation completed successfully")
            consecutive_failures = 0  # Reset failure counter on success
            
        except asyncio.CancelledError:
            logger.info("Scheduler loop cancelled")
            raise
        except Exception as e:
            consecutive_failures += 1
            logger.error("Scheduled generation failed (attempt %d/%d): %s", 
                        consecutive_failures, max_consecutive_failures, e)
            
            if consecutive_failures >= max_consecutive_failures:
                logger.critical("Maximum consecutive failures reached, extending retry delay")
                await asyncio.sleep(300)  # 5 minute delay after multiple failures
            else:
                await asyncio.sleep(30)  # 30 second delay for single failures


@app.on_event("startup")
async def on_startup():
    app.state.scheduler_task = asyncio.create_task(scheduler_loop())
    # Initialize credentials on startup
    creds = load_or_create_credentials()
    logger.info("Xtreme Codes API credentials ready")
    logger.info(f"Toonami Aftermath: Downlink running on http://localhost:{PORT}")
    logger.info("View full credentials and setup guide in WebUI")
    
    # Show first-time setup info if this is a new installation
    created_recently = False
    try:
        created_at = datetime.fromisoformat(creds.get('created_at', ''))
        time_since_creation = datetime.now(timezone.utc) - created_at
        created_recently = time_since_creation.total_seconds() < 60  # Created in last minute
    except Exception:
        pass
        
    if created_recently:
        logger.info("Welcome! This appears to be your first launch.")
        logger.info("Your unique IPTV credentials are ready to use.")
        logger.info("No configuration needed - everything works out of the box!")


def create_app():
    """Create and configure the FastAPI application instance."""
    return app
