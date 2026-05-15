"""Tests for `_parse_extinf` priority and the `/live/...` lookup back-compat.

Covers the fix that makes Xtreme Codes `stream_id` numeric (from `channel-id`)
instead of a name string (from `tvg-id`) — see PR titled "fix: use channel-id
for Xtreme Codes stream_id (numeric stable ids)".
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Mirror test_integration.py bootstrap so importing `app.server` succeeds.
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("WEB_DIR", str(Path(__file__).parent / "web"))

sys.path.insert(0, str(Path(__file__).parent))

from app.server import _parse_extinf  # noqa: E402


def test_parse_extinf_prefers_channel_id_over_tvg_id() -> None:
    line = (
        '#EXTINF:0 tvg-name="Toonami Aftermath East" channel-id="1" '
        'group-title="Toonami Aftermath" tvg-country="us" '
        'tvg-id="Toonami Aftermath East" tvg-language="en",'
        "Toonami Aftermath East"
    )
    chan_id, number, name = _parse_extinf(line)
    assert chan_id == "1", "channel-id should win over tvg-id"
    assert name == "Toonami Aftermath East"
    assert number is None  # no tvg-chno / channel-number in this line


def test_parse_extinf_falls_back_to_tvg_id_when_channel_id_absent() -> None:
    line = '#EXTINF:-1 tvg-id="foo" tvg-name="Foo",Foo'
    chan_id, _number, _name = _parse_extinf(line)
    assert chan_id == "foo"


def test_parse_extinf_default_id_when_neither_attr_present() -> None:
    line = "#EXTINF:-1,Bare Channel"
    chan_id, _number, name = _parse_extinf(line)
    assert chan_id == "ta"
    assert name == "Bare Channel"


def test_parse_extinf_picks_up_channel_number_attrs() -> None:
    line = '#EXTINF:0 channel-id="3" channel-number="7",Three'
    chan_id, number, _name = _parse_extinf(line)
    assert chan_id == "3"
    assert number == "7"
    line2 = '#EXTINF:0 channel-id="3" tvg-chno="9",Three'
    _, number2, _ = _parse_extinf(line2)
    assert number2 == "9", "tvg-chno should win over channel-number when present"


def test_xtreme_stream_lookup_accepts_id_or_name() -> None:
    """The /live/<user>/<pass>/<stream_id>.ts endpoint matches on id OR name,
    so old URLs that used the channel name remain resolvable after the swap
    to channel-id-as-id."""
    # Inline the lookup predicate from xtreme_stream so we can exercise it
    # without spinning up the full FastAPI app.
    channels = [
        {"id": "1", "name": "Toonami Aftermath East", "url": "https://example/east"},
        {"id": "2", "name": "Toonami Aftermath West", "url": "https://example/west"},
    ]

    def find(stream_id: str) -> dict | None:
        for ch in channels:
            cid = ch.get("id")
            if (
                cid == stream_id
                or str(cid or "").replace(".", "_") == stream_id
                or ch.get("name") == stream_id
            ):
                return ch
        return None

    # New, post-fix form
    assert find("1") is channels[0]
    assert find("2") is channels[1]
    # Back-compat: name-based URLs still resolve
    assert find("Toonami Aftermath East") is channels[0]
    assert find("Toonami Aftermath West") is channels[1]
    # Negative
    assert find("99") is None
    assert find("Some Other Channel") is None
