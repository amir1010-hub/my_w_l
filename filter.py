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

# Edit this expression to adjust selection. It is applied ONLY to proxy names.
# Supported examples: white, white list, whitelist, bypass, allowlist,
# обход, обходной, белые, белых, белый, вайтлист, разблокировка.

"""NAME_PATTERN = re.compile(
    r"\b(?:"
    r"white(?:[\s._-]*lists?)?"
    r"|bypass"
    r"|allow[\s._-]*lists?"
    r"|обход\w*"
    r"|обойти"
    r"|обхождени\w*"
    r"|разблок\w*"
    r"|вайт\w*"
    r"|бел(?:ый|ые|ых|ого|ому|ым|ыми|ая|ой|ую|ое|ом)"
    r")\b",
    re.IGNORECASE | re.UNICODE,
)"""

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
                if not text.strip():
                    raise ValueError("Source is empty")
                return text
        except (OSError, UnicodeError, ValueError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Failed to fetch source: {last_error}")


def previous_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(line.strip().lower().startswith(SCHEMES)
               for line in path.read_text(encoding="utf-8-sig").splitlines())


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=SOURCE_URL, help="URL of upstream subscription")
    parser.add_argument("--input", type=Path, help="Local text file instead of downloading")
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    parser.add_argument("--report", type=Path, default=Path("subscriptions/health-report.json"))
    parser.add_argument("--ping-mode", choices=("tcp", "off"), default="tcp",
                        help="tcp = validate endpoint reachability; off = name-only filtering")
    parser.add_argument("--timeout", type=float, default=2.5, help="Per TCP connect timeout, seconds")
    parser.add_argument("--attempts", type=int, default=2, help="Attempts per endpoint")
    parser.add_argument("--workers", type=int, default=12, help="Parallel TCP probes")
    parser.add_argument("--allow-empty", action="store_true", help="For ping-mode off only; don't use in production")
    args = parser.parse_args()
    if not (0.2 <= args.timeout <= 20 and 1 <= args.attempts <= 5 and 1 <= args.workers <= 64):
        parser.error("Use timeout 0.2–20s, attempts 1–5, workers 1–64")

    try:
        source = args.input.read_text(encoding="utf-8-sig") if args.input else fetch(args.source)
        selected, total = filter_links(source)
        if total == 0:
            raise ValueError("No supported proxy links in source; existing file left unchanged")
        if not selected and not args.allow_empty:
            raise ValueError("No matching names; existing file left unchanged")

        previous = previous_count(args.output)
        if args.ping_mode == "tcp":
            results = check_all(selected, args.timeout, args.attempts, args.workers)
            chosen, summary = build_live_set(selected, results, previous)
        else:
            results = [ProbeResult("unsupported") for _ in selected]
            chosen = selected
            summary = {"input": len(selected), "published": len(chosen),
                       "ok": 0, "failed": 0, "unsupported": len(chosen), "unsafe": 0}
        if not chosen and not args.allow_empty:
            raise ValueError("Selected list is empty; existing file left unchanged")

        header = [
            "#profile-title: White / Bypass (filtered rjsxrd)",
            "#profile-update-interval: 1",
            "#announce: Auto-filtered rjsxrd; TCP reachability checked (not full proxy validation)",
        ]
        content = "\n".join([*header, *chosen]) + "\n"
        # Report excludes credentials, proxy URLs, and remote host addresses.
        report = {
            "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": args.source if not args.input else "local input",
            "probe": "TCP connect" if args.ping_mode == "tcp" else "disabled",
            "upstream_links": total,
            **summary,
            "entries": [
                {"name": proxy_name(link), "protocol": link.split("://", 1)[0],
                 "status": result.status, "tcp_ms": result.latency_ms}
                for link, result in zip(selected, results)
            ],
        }
        # Only publish if health guard was passed; error above leaves files untouched.
        atomic_write(args.output, content)
        atomic_write(args.report, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"Upstream: {total}; name match: {len(selected)}; published: {len(chosen)}")
        print(f"TCP OK: {summary['ok']}; failed: {summary['failed']}; "
              f"untested: {summary['unsupported']}; unsafe: {summary['unsafe']}")
        print(f"Saved: {args.output} | report: {args.report}")
        for link, result in zip(selected, results):
            if result.status == "ok":
                print(f"  {result.latency_ms:7.1f} ms  {proxy_name(link)[:75]}")
            elif result.status != "unsupported":
                print(f"  {result.status.upper():>9}  {proxy_name(link)[:75]}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
