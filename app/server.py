import os
import json
import shutil
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, Response, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from .xtreme_codes import (
    load_or_create_credentials, verify_credentials, get_server_info,
    generate_short_epg, format_xtreme_m3u
)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
PORT = int(os.environ.get("PORT", "7004"))
CRON_SCHEDULE = os.environ.get("CRON_SCHEDULE", "0 3 * * *")
# Try to find the CLI binary - use mock for Windows development
CLI_BIN_PATHS = [
    Path("/usr/local/bin/toonamiaftermath-cli"),  # Docker/Linux
    Path(__file__).parent.parent / "mock_cli.py"  # Local development fallback
]

# Allow environment override for CLI binary path
CLI_BIN: Optional[Path] = None
env_cli = os.environ.get("CLI_BIN")
if env_cli:
    try:
        candidate = Path(env_cli)
        if candidate.exists():
            CLI_BIN = candidate
    except Exception:
        CLI_BIN = None

# Fallback to known locations if no env override or not found
if CLI_BIN is None:
    for path in CLI_BIN_PATHS:
        if path.exists():
            CLI_BIN = path
            break

# As a last resort, default to the first path (may not exist yet)
if CLI_BIN is None:
    CLI_BIN = CLI_BIN_PATHS[0]

# Constants
MIME_M3U = "application/x-mpegURL"
MIME_XML = "application/xml"
MSG_INVALID_CREDENTIALS = "Invalid credentials"

M3U_PATH = DATA_DIR / "index.m3u"
XML_PATH = DATA_DIR / "index.xml"
STATE_PATH = DATA_DIR / "state.json"

app = FastAPI(title="Toonami Aftermath: Downlink")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"]
)

# Mount Web UI
WEB_DIR = Path(os.environ.get("WEB_DIR", "/web")).resolve()

# Only mount static files if the directory exists
def setup_web_routes():
    if (WEB_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")
    
    @app.get("/")
    def web_index():
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
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}
    return {}


def write_state(state: Dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


async def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> int:
    # Handle Python mock CLI
    if str(cmd[0]).endswith("mock_cli.py"):
        cmd = ["python", str(cmd[0])] + cmd[1:]

    logger.info("Executing: %s%s", " ".join(cmd), f" (cwd={cwd})" if cwd else "")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd
    )
    assert proc.stdout
    async for line in proc.stdout:
        logger.info(line.decode(errors="ignore").rstrip())
    return await proc.wait()


def ensure_cli_exists() -> None:
    """Ensure CLI binary exists."""
    if not CLI_BIN.exists():
        raise RuntimeError(f"toonamiaftermath-cli not found at {CLI_BIN}")


async def generate_files() -> Dict[str, Any]:
    ensure_cli_exists()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Generating M3U and XMLTV via toonamiaftermath-cli (%s)", CLI_BIN)

    # Try multiple invocation strategies to support different CLI versions
    attempts: List[Tuple[List[str], Optional[str]]] = [
        ([str(CLI_BIN), "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN), "run", "-m", str(M3U_PATH), "-x", str(XML_PATH)], None),
        ([str(CLI_BIN)], str(DATA_DIR)),                   # defaults to index.* in cwd
        ([str(CLI_BIN), "run"], str(DATA_DIR)),          # some versions require subcommand
    ]

    success = False
    for cmd, cwd in attempts:
        try:
            rc = await run_cmd(cmd, cwd=cwd)
        except Exception as e:
            logger.warning("CLI execution failed for '%s': %s", " ".join(cmd), e)
            continue

        # If explicit paths were provided, check them directly
        if M3U_PATH.exists() and XML_PATH.exists():
            success = True
            break

        # Otherwise, check common defaults in DATA_DIR (and legacy /app)
        default_m3u_candidates = [DATA_DIR / "index.m3u", Path("/app/index.m3u")] 
        default_xml_candidates = [DATA_DIR / "index.xml", Path("/app/index.xml")] 
        for dm in default_m3u_candidates:
            if dm.exists() and dm != M3U_PATH:
                try:
                    shutil.move(str(dm), str(M3U_PATH))
                except Exception:
                    shutil.copyfile(str(dm), str(M3U_PATH))
        for dx in default_xml_candidates:
            if dx.exists() and dx != XML_PATH:
                try:
                    shutil.move(str(dx), str(XML_PATH))
                except Exception:
                    shutil.copyfile(str(dx), str(XML_PATH))

        if M3U_PATH.exists() and XML_PATH.exists():
            success = True
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
    return state


async def get_cli_version() -> Optional[str]:
    try:
        cmd = [str(CLI_BIN), "--version"]
        # Handle Python mock CLI
        if str(CLI_BIN).endswith("mock_cli.py"):
            cmd = ["python", str(CLI_BIN), "--version"]
        
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        return out.decode().strip() or None
    except Exception:
        return None


def _parse_extinf(line: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
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


def parse_channels_from_m3u() -> List[Dict[str, Any]]:
    channels: List[Dict[str, Any]] = []
    if not M3U_PATH.exists():
        return channels
    try:
        pending: Optional[Dict[str, Any]] = None
        for raw in M3U_PATH.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#EXTINF"):
                chan_id, number, name = _parse_extinf(line)
                pending = {"id": chan_id, "number": number, "name": name}
            elif not line.startswith("#") and pending and pending.get("name"):
                pending["url"] = line
                channels.append(pending)
                pending = None
    except Exception as e:
        logger.warning("Failed parsing M3U: %s", e)
    return channels


@app.get("/status")
async def status():
    state = read_state()
    last_update = state.get("last_update")
    cron = os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE)
    cli_version = state.get("cli_version")
    return {
        "last_update": last_update,
        "next_run": app.state.scheduler_next_run if hasattr(app.state, 'scheduler_next_run') else None,
        "cron": cron,
        "cli_version": cli_version,
        "channel_count": len(parse_channels_from_m3u()),
        "stream_endpoints_available": True
    }


@app.get("/m3u")
async def get_m3u():
    """Standard M3U playlist without stream codes."""
    if not M3U_PATH.exists():
        raise HTTPException(status_code=404, detail="M3U not yet generated")
    return Response(M3U_PATH.read_bytes(), media_type=MIME_M3U)


@app.get("/m3u/stream-codes/{stream_code}")
async def get_m3u_with_stream_code(stream_code: str):
    """M3U playlist with stream codes appended to URLs."""
    if not M3U_PATH.exists():
        raise HTTPException(status_code=404, detail="M3U not yet generated")
    
    content = M3U_PATH.read_text(errors="ignore")
    lines = []
    for line in content.splitlines():
        if line.strip() and not line.startswith("#"):
            # This is a URL line, add stream code
            if "?" in line:
                line = f"{line}&code={stream_code}"
            else:
                line = f"{line}?code={stream_code}"
        lines.append(line)
    return Response("\n".join(lines), media_type=MIME_M3U)


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
    # Verify credentials
    if not username or not password or not verify_credentials(username, password):
        return JSONResponse({"user_info": {"auth": 0}}, status_code=401)
    
    request.state.username = username
    request.state.password = password
    
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
    if not username or not password or not verify_credentials(username, password):
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    
    channels = parse_channels_from_m3u()
    host = request.headers.get("host", "localhost")
    
    m3u_content = format_xtreme_m3u(channels, host, username, password)
    return Response(m3u_content, media_type=MIME_M3U)


@app.get("/xmltv.php")
async def xtreme_xmltv(
    username: str = Query(None),
    password: str = Query(None)
):
    """Xtreme Codes XMLTV endpoint."""
    if not username or not password or not verify_credentials(username, password):
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    
    if not XML_PATH.exists():
        raise HTTPException(status_code=404, detail="XML not yet generated")
    
    return Response(XML_PATH.read_bytes(), media_type=MIME_XML)


@app.get("/live/{username}/{password}/{stream_id}.{ext}")
async def xtreme_stream(
    username: str,
    password: str,
    stream_id: str,
    ext: str
):
    """Xtreme Codes live stream redirect."""
    if not verify_credentials(username, password):
        return PlainTextResponse(MSG_INVALID_CREDENTIALS, status_code=401)
    
    # Find the actual stream URL
    channels = parse_channels_from_m3u()
    for ch in channels:
        if ch.get("id") == stream_id or str(ch.get("id", "")).replace(".", "_") == stream_id:
            stream_url = ch.get("url", "")
            if stream_url:
                return RedirectResponse(url=stream_url, status_code=302)
    
    raise HTTPException(status_code=404, detail="Stream not found")


@app.get("/credentials")
async def get_credentials(request: Request):
    """Get Xtreme Codes credentials for this installation."""
    creds = load_or_create_credentials()
    host = request.headers.get('host', 'localhost:7004')
    protocol = "https" if request.url.scheme == "https" else "http"
    
    return {
        "username": creds.get("username"),
        "password": creds.get("password"),
        "created_at": creds.get("created_at"),
        "installation_id": creds.get("installation_id"),
        "server_url": host,
        "instructions": "Use these credentials in your IPTV player's Xtreme Codes API settings",
        "setup_guide": {
            "tivimate": "Add M3U Playlist → Xtreme Codes → Enter server, username, password",
            "iptv_smarters": "Add Playlist → Xtreme Codes → Enter server URL, username, password", 
            "perfect_player": "Settings → Playlist → Add → Xtreme Codes → Enter details"
        },
        "direct_urls": {
            "standard_m3u": f"{protocol}://{host}/m3u",
            "standard_xml": f"{protocol}://{host}/xml",
            "xtreme_m3u": f"{protocol}://{host}/get.php?username={creds.get('username')}&password={creds.get('password')}&type=m3u_plus",
            "xtreme_xml": f"{protocol}://{host}/xmltv.php?username={creds.get('username')}&password={creds.get('password')}"
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


# Simple cron scheduler with aiocron-like behavior but without deps
import re
CRON_RE = re.compile(r"^\s*([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s+([0-9*,/\-]+)\s*$")

from datetime import timedelta

def cron_next(dt: datetime, expr: str) -> Optional[datetime]:
    # Minimal: support "m h dom mon dow" with *, number, and step (*/N) for minute/hour.
    m = CRON_RE.match(expr)
    if not m:
        base = dt.replace(hour=3, minute=0, second=0, microsecond=0)
        return base if base > dt else base + timedelta(days=1)
    mins, hrs, dom, mon, dow = m.groups()
    def parse_field(val: str, _default: int) -> Tuple[str, Optional[int]]:
        if val == "*":
            return "any", None
        if val.startswith("*/") and val[2:].isdigit():
            return "step", int(val[2:])
        if val.isdigit():
            return "fixed", int(val)
        return "invalid", None

    min_mode, min_val = parse_field(mins, 0)
    hr_mode, hr_val = parse_field(hrs, 3)
    if "invalid" in (min_mode, hr_mode) or any(x not in ("*",) and not x.isdigit() for x in (dom, mon, dow)):
        base = dt.replace(hour=3, minute=0, second=0, microsecond=0)
        return base if base > dt else base + timedelta(days=1)
    # Compute next
    candidate = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(0, 24*60 + 2):  # search up to ~1 day
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
        if ok_min and ok_hr:
            return candidate
        candidate += timedelta(minutes=1)
    # fallback
    base = dt.replace(hour=3, minute=0, second=0, microsecond=0)
    return base if base > dt else base + timedelta(days=1)


async def scheduler_loop():
    # initial run at startup
    try:
        await generate_files()
    except Exception as e:
        logger.error("Initial generation failed: %s", e)
    while True:
        now = datetime.now(timezone.utc)
        next_run = cron_next(now, os.environ.get("CRON_SCHEDULE", CRON_SCHEDULE))
        app.state.scheduler_next_run = next_run.isoformat() if next_run else None
        delay = max(5.0, (next_run - now).total_seconds() if next_run else 3600)
        logger.info("Next scheduled run at %s (in %.0fs)", next_run, delay)
        try:
            await asyncio.sleep(delay)
            await generate_files()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Scheduled generation failed: %s", e)
            await asyncio.sleep(30)


@app.on_event("startup")
async def on_startup():
    app.state.scheduler_task = asyncio.create_task(scheduler_loop())
    # Initialize credentials on startup
    creds = load_or_create_credentials()
    logger.info("Xtreme Codes API credentials ready")
    logger.info(f"Username: {creds.get('username')}")
    logger.info(f"Toonami Aftermath: Downlink running on http://localhost:{PORT}")
    logger.info("View full credentials and setup guide in WebUI")
    
    # Show first-time setup info if this is a new installation
    created_recently = False
    try:
        created_at = datetime.fromisoformat(creds.get('created_at', ''))
        time_since_creation = datetime.now(timezone.utc) - created_at
        created_recently = time_since_creation.total_seconds() < 60  # Created in last minute
    except:
        pass
        
    if created_recently:
        logger.info("Welcome! This appears to be your first launch.")
        logger.info("Your unique IPTV credentials are ready to use.")
        logger.info("No configuration needed - everything works out of the box!")


def create_app():
    return app
