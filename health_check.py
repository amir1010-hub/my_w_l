"""Non-ICMP TCP reachability tests for public proxy endpoints.

A successful TCP connection does NOT verify VLESS/Reality credentials or
that a proxy tunnels traffic. rjsxrd upstream already runs Xray verification.
Unsupported UDP-only protocols are kept and identified as untested.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import ipaddress
import json
import re
import socket
import time
from urllib.parse import unquote, urlsplit

UDP_ONLY = {"hy2", "hysteria2", "tuic", "hysteria"}


def decode_b64(value: str) -> str:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")


def endpoint(link: str) -> tuple[str, int] | None:
    """Extract a connectable host and port from common share links.

    Return None for UDP-only protocols and unrecognised layouts.
    """
    scheme = link.split("://", 1)[0].lower()
    if scheme in UDP_ONLY:
        return None
    try:
        if scheme == "vmess":
            obj = json.loads(decode_b64(link.split("://", 1)[1].split("#", 1)[0]))
            host, port = str(obj["add"]), int(obj["port"])
        elif scheme == "ssr":
            payload = decode_b64(link.split("://", 1)[1].split("#", 1)[0])
            # Expected: host:port:protocol:cipher:obfs:password[/...]
            match = re.match(r"^(.*?):(\d+):[^:]*:[^:]*:[^:]*:", payload)
            if not match:
                return None
            host, port = match.group(1), int(match.group(2))
        elif scheme == "ss":
            parsed = urlsplit(link)
            if "@" in parsed.netloc:
                host, port = parsed.hostname, parsed.port
            else:
                # Legacy ss://base64(method:password@host:port)
                decoded = decode_b64(parsed.netloc)
                if "@" not in decoded:
                    return None
                target = decoded.rsplit("@", 1)[1]
                parsed2 = urlsplit("tcp://" + target)
                host, port = parsed2.hostname, parsed2.port
        else:
            parsed = urlsplit(link)
            host, port = parsed.hostname, parsed.port
        if not host or not port or not (1 <= port <= 65535):
            return None
        # Host itself should not be a URL or contain spaces.
        if any(c.isspace() for c in host) or any(c in host for c in ("/", "#", "@")):
            return None
        return unquote(host), port
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError, OverflowError):
        return None


@dataclass(frozen=True)
class ProbeResult:
    status: str  # ok | failed | unsupported | unsafe
    latency_ms: float | None = None


def ping_tcp(host: str, port: int, timeout: float = 2.5, attempts: int = 2) -> ProbeResult:
    """Measure TCP connect time to public IPs only (no ICMP ping)."""
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return ProbeResult("failed")

    candidates = []
    for family, socktype, proto, _canon, sockaddr in addresses:
        try:
            addr = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
            # Never probe loopback, private, link-local, or reserved IPs.
            if addr.is_global and (family, socktype, proto, sockaddr) not in candidates:
                candidates.append((family, socktype, proto, sockaddr))
        except ValueError:
            continue
    if not candidates:
        return ProbeResult("unsafe")
    # IPv4 is usually available from GitHub runners; probe it first to avoid
    # declaring IPv4-capable endpoints dead because IPv6 routing failed.
    candidates.sort(key=lambda item: item[0] != socket.AF_INET)

    # Limit attempts across all resolved IPv4/IPv6 addresses.
    best = None
    for index in range(max(1, attempts)):
        family, socktype, proto, sockaddr = candidates[index % len(candidates)]
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                start = time.perf_counter()
                sock.connect(sockaddr)
                latency = round((time.perf_counter() - start) * 1000, 1)
                best = latency if best is None else min(best, latency)
                # One success suffices; extra connect attempts are unnecessary.
                break
        except OSError:
            pass
    return ProbeResult("ok", best) if best is not None else ProbeResult("failed")


def classify(link: str, timeout: float, attempts: int) -> ProbeResult:
    target = endpoint(link)
    if target is None:
        return ProbeResult("unsupported")
    return ping_tcp(*target, timeout=timeout, attempts=attempts)


def check_all(links: list[str], timeout: float, attempts: int, workers: int) -> list[ProbeResult]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda link: classify(link, timeout, attempts), links))


def build_live_set(
    links: list[str], results: list[ProbeResult],
    previous_count: int = 0, min_ratio: float = 0.35,
) -> tuple[list[str], dict]:
    """Keep reachable TCP servers + UDP/unknown untouched; fail closed on mass loss."""
    if len(links) != len(results):
        raise ValueError("Results do not match input count")
    summary = {status: sum(r.status == status for r in results)
               for status in ("ok", "failed", "unsupported", "unsafe")}
    tcp_tested = summary["ok"] + summary["failed"] + summary["unsafe"]
    if tcp_tested and summary["ok"] == 0:
        raise ValueError("All TCP probes failed. Keeping previously published subscription unchanged.")
    if tcp_tested >= 4 and summary["ok"] / tcp_tested < 0.25:
        raise ValueError("Under 25% of TCP endpoints reachable. Suspected GitHub network issue; previous file kept.")
    # Unprobed protocols are included because TCP is not a valid verification for UDP.
    kept = [(link, result) for link, result in zip(links, results)
            if result.status in ("ok", "unsupported")]
    if not kept:
        raise ValueError("No usable or untested configs. Keeping previous subscription unchanged.")
    if previous_count >= 4 and len(kept) < previous_count * min_ratio:
        raise ValueError(f"Abrupt drop ({previous_count} -> {len(kept)} links). Previous file kept.")

    # Stable order from upstream; upstream file is already sorted by real proxy latency.
    return [link for link, _ in kept], {**summary, "input": len(links), "published": len(kept)}
