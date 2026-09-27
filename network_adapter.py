"""Bounded HTTP GET through an exact-origin network capability."""

from __future__ import annotations

import hashlib
import http.client
import socket
from urllib.parse import urlsplit


MAX_BODY = 64 * 1024
TIMEOUT_SECONDS = 5


def origin_and_target(url: str) -> tuple[str, str, str, int, str]:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 for c in url):
        raise ValueError("invalid URL")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("HTTP or HTTPS URL required")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("URL credentials and fragments are forbidden")
    host = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    display_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{display_host}:{port}"
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return origin, parsed.scheme, host, port, target


def fetch(url: str, allowed_origins: list[str]) -> dict:
    origin, scheme, host, port, target = origin_and_target(url)
    normalized = {origin_and_target(item)[0] for item in allowed_origins}
    if origin not in normalized:
        raise ValueError("destination not allowed")

    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError("destination did not resolve")
    # http.client keeps the original host for Host and TLS SNI; the TCP address is pinned.
    address = addresses[0][4][0]

    def connect_pinned(_address, timeout, source_address=None):
        return socket.create_connection((address, port), timeout, source_address)

    connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    connection = connection_type(host, port, timeout=TIMEOUT_SECONDS)
    connection._create_connection = connect_pinned
    try:
        connection.request("GET", target, headers={"User-Agent": "gov-substrate/0.2"})
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response exceeds 64 KiB")
        return {
            "status": response.status,
            "body": body.decode("utf-8", errors="replace"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "bytes": len(body),
            "origin": origin,
            "resolved_ip": address,
        }
    finally:
        connection.close()
