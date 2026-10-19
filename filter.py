
#!/usr/bin/env python3
"""Create a filtered share-link subscription from rjsxrd bypass-all.txt.

Matches ONLY user-visible proxy labels (#fragment or vmess ps), not IP, SNI,
query parameters or credential material. No third-party packages required.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import time
import unicodedata
from datetime import datetime, timezone

from health_check import ProbeResult, build_live_set, check_all
from urllib.parse import unquote
from urllib.request import Request, urlopen

SOURCE_URL = os.getenv(
    "RJSXRD_SOURCE_URL",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass/bypass-all.txt",
)
DEFAULT_OUTPUT = "subscriptions/white-bypass.txt"
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy2://", "hysteria2://", "tuic://", "socks://")

# Only proxy names containing "AetrisVPN White list" (case-insensitive) are selected.
# Spaces, hyphens, underscores and dots are accepted between the words.
NAME_PATTERN = re.compile(
    r"\baetrisvpn[\s._-]+white[\s._-]+list\b",
    re.IGNORECASE | re.UNICODE,
)


def vmess_name(line: str) -> str:
    """Extract vmess ps from base64-encoded JSON, if provided."""
    payload = line[len("vmess://"):].split("#", 1)[0].strip()
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        data = json.loads(decoded.decode("utf-8-sig"))
        if isinstance(data, dict):
            return str(data.get("ps") or "")
    except (ValueError, UnicodeError, TypeError):
        pass
    return ""


def proxy_name(line: str) -> str:
    """Name only: vmess.ps or URL fragment, never entire URL."""
    if line.lower().startswith("vmess://"):
        name = vmess_name(line)
        if name:
            return unicodedata.normalize("NFKC", name)
    if "#" in line:
        return unicodedata.normalize("NFKC", unquote(line.split("#", 1)[1]))
    return ""


def matches(line: str) -> bool:
    return bool(NAME_PATTERN.search(proxy_name(line)))


def filter_links(text: str) -> tuple[list[str], int]:
    """Return selected links, preserving their original encoding and order."""
    selected = []
    seen = set()
    total = 0
    for raw in text.lstrip("\ufeff").splitlines():
        line = raw.strip()
        if not line.lower().startswith(SCHEMES):
            continue
        total += 1
        if not matches(line):
            continue
        # Same credentials/endpoint with different captions = duplicate.
        key = line.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        selected.append(line)
    return selected, total


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "rjsxrd-white-filter/1.0", "Accept": "text/plain"})
    last_error = None
    for attempt in range(3):
        try:
            with urlopen(req, timeout=30) as response:
                data = response.read(8_000_001)
                if len(data) > 8_000_000:
                    raise ValueError("Input is bigger than 8 MB")
                text = data.decode("utf-8-sig")
