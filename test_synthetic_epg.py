"""Tests for the synthetic-EPG fallback (`_synthesize_missing_epg`).

Channels MTV97, Movies, and Toonami Aftermath Radio have no upstream
schedule on `api.toonamiaftermath.com`, so the CLI emits `<channel>`
elements without any matching `<programme>` entries. We post-process
the XMLTV to inject per-day 'always-on' programmes for those channels
so Plex / Channels DVR / Jellyfin show a useful label in the guide.
"""

from __future__ import annotations

import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

# Mirror test_integration.py bootstrap so importing `app.server` succeeds.
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("WEB_DIR", str(Path(__file__).parent / "web"))

sys.path.insert(0, str(Path(__file__).parent))

from app import server  # noqa: E402
from app.server import (  # noqa: E402
    _format_xmltv_time,
    _synthesize_missing_epg,
)


def _write_xml(tmp_path: Path, *, has_mtv_programme: bool = False) -> Path:
    """Build a sample index.xml that mimics what the CLI emits."""
    root = ET.Element("tv")
    for cid, name in [
        ("1", "Toonami Aftermath East"),
        ("2", "Toonami Aftermath West"),
        ("5", "MTV97"),
        ("6", "Movies"),
        ("7", "Toonami Aftermath Radio"),
    ]:
        ch = ET.SubElement(root, "channel", {"id": cid})
        ET.SubElement(ch, "display-name", {"lang": "en"}).text = name

    # Real programme for TA East so it's NOT a "missing" channel.
    p = ET.SubElement(
        root,
        "programme",
        {"start": "20260515000000 +0000", "stop": "20260515003000 +0000", "channel": "1"},
    )
    ET.SubElement(p, "title", {"lang": "en"}).text = "Lupin III"

    if has_mtv_programme:
        # Edge case: MTV already has a programme (don't double up).
        p2 = ET.SubElement(
            root,
            "programme",
            {"start": "20260515000000 +0000", "stop": "20260515010000 +0000", "channel": "5"},
        )
        ET.SubElement(p2, "title").text = "MTV — Existing entry"

    out = tmp_path / "index.xml"
    ET.ElementTree(root).write(out, encoding="utf-8", xml_declaration=True)
    return out


def _count_programmes(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    counts: dict[str, int] = {}
    for p in root.findall("programme"):
        cid = p.get("channel", "")
        counts[cid] = counts.get(cid, 0) + 1
    return counts


def test_synthesize_fills_only_empty_channels(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(server, "XML_PATH", _write_xml(tmp_path))
    monkeypatch.setenv("SYNTHETIC_EPG_DAYS", "3")

    augmented = _synthesize_missing_epg()
    assert augmented == 4, "All 4 channels lacking programmes should be filled"

    counts = _count_programmes(server.XML_PATH)
    # TA East had 1 real programme; should be untouched.
    assert counts.get("1") == 1
    # The 4 channels without upstream data should each get 3 daily blocks.
    for cid in ("2", "5", "6", "7"):
        assert counts.get(cid) == 3, f"channel {cid} should have 3 synthetic entries"


def test_synthesize_uses_curated_title_when_known(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(server, "XML_PATH", _write_xml(tmp_path))
    monkeypatch.setenv("SYNTHETIC_EPG_DAYS", "1")
    _synthesize_missing_epg()

    root = ET.parse(server.XML_PATH).getroot()
    # MTV97 (channel id 5) should pick up the curated synthetic title.
    mtv_titles = [
        p.findtext("title") for p in root.findall("programme") if p.get("channel") == "5"
    ]
    assert mtv_titles == ["MTV97 — Late-90s MTV Block"]

    # An "unknown" channel without a curated entry should fall back to a
    # generic title built from its display name. TA West (id 2) is in our
    # known set as "Toonami Aftermath West" but it's NOT in SYNTHETIC_PROGRAMMES
    # by default — verify fallback.
    west_titles = [
        p.findtext("title") for p in root.findall("programme") if p.get("channel") == "2"
    ]
    assert west_titles == ["Toonami Aftermath West — Live Stream"]


def test_synthesize_is_noop_when_all_channels_have_programmes(
    monkeypatch, tmp_path: Path
) -> None:
    # Build an XML where every channel has at least one programme.
    root = ET.Element("tv")
    for cid, name in [("1", "TA East"), ("2", "TA West")]:
        ch = ET.SubElement(root, "channel", {"id": cid})
        ET.SubElement(ch, "display-name").text = name
        p = ET.SubElement(
            root,
            "programme",
            {"start": "20260515000000 +0000", "stop": "20260515003000 +0000", "channel": cid},
        )
        ET.SubElement(p, "title").text = f"Show on {name}"
    path = tmp_path / "index.xml"
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

    monkeypatch.setattr(server, "XML_PATH", path)
    assert _synthesize_missing_epg() == 0

    counts = _count_programmes(path)
    assert counts == {"1": 1, "2": 1}, "Existing programmes must not be touched"


def test_synthesize_handles_missing_xml(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(server, "XML_PATH", tmp_path / "does-not-exist.xml")
    assert _synthesize_missing_epg() == 0


def test_format_xmltv_time_naive_and_aware_match() -> None:
    naive = datetime(2026, 5, 15, 12, 30, 0)
    aware = datetime(2026, 5, 15, 12, 30, 0, tzinfo=UTC)
    assert _format_xmltv_time(naive) == "20260515123000 +0000"
    assert _format_xmltv_time(aware) == "20260515123000 +0000"


def test_synthesize_clamps_invalid_days_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(server, "XML_PATH", _write_xml(tmp_path))
    monkeypatch.setenv("SYNTHETIC_EPG_DAYS", "not-a-number")
    _synthesize_missing_epg()
    # Falls back to the module default (7) when env var is non-numeric.
    counts = _count_programmes(server.XML_PATH)
    assert counts.get("5") == server.SYNTHETIC_EPG_DAYS_AHEAD
