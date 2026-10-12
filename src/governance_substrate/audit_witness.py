"""Append-only audit witnesses outside the substrate database."""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class AuditWitness(Protocol):
    def append(self, event_id: int, event_hash: str, previous_hash: str) -> None: ...
    def verify(self, event_id: int, event_hash: str) -> bool: ...


@dataclass(frozen=True)
class MTLSAuditWitness:
    """Replicate audit heads to an independent HTTPS service using mutual TLS."""

    url: str
    ca_file: str
    certificate_file: str
    private_key_file: str
    timeout_seconds: float = 5.0

    def _request(self, path: str, payload: dict) -> dict:
        context = ssl.create_default_context(cafile=self.ca_file)
        context.load_cert_chain(self.certificate_file, self.private_key_file)
        request = Request(
            self.url.rstrip("/") + path,
            data=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=context) as response:
                result = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise RuntimeError(f"audit witness unavailable: {type(exc).__name__}") from None
        if type(result) is not dict:
            raise RuntimeError("audit witness returned an invalid response")
        return result

    def append(self, event_id: int, event_hash: str, previous_hash: str) -> None:
        result = self._request("/append", {
            "event_id": event_id,
            "event_hash": event_hash,
            "previous_hash": previous_hash,
        })
        if result != {"accepted": True, "event_id": event_id, "event_hash": event_hash}:
            raise RuntimeError("audit witness rejected the event")

    def verify(self, event_id: int, event_hash: str) -> bool:
        return self._request("/verify", {
            "event_id": event_id,
            "event_hash": event_hash,
        }) == {"verified": True, "event_id": event_id, "event_hash": event_hash}


def serve_witness():
    """Serve the existing append/verify contract with durable, role-bound mTLS."""
    import hashlib
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    path = Path(os.environ['WITNESS_PATH'])
    lock = threading.Lock()
    entries = []
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            item = json.loads(line)
            previous = entries[-1]['event_hash'] if entries else '0' * 64
            if item['event_id'] != len(entries) + 1 or item['previous_hash'] != previous:
                raise RuntimeError('witness_journal_corrupt')
            entries.append(item)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            identity = next((value for part in self.connection.getpeercert().get('subject', [])
                             for key, value in part if key == 'commonName'), None)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2048:
                self.send_error(400); return
            body = json.loads(self.rfile.read(length))
            with lock:
                head = entries[-1] if entries else {'event_id': 0, 'event_hash': '0' * 64}
                if self.path == '/append':
                    if identity != 'substrate':
                        self.send_error(403); return
                    if (body.get('event_id') != head['event_id'] + 1 or
                            body.get('previous_hash') != head['event_hash'] or
                            not isinstance(body.get('event_hash'), str) or
                            len(body['event_hash']) != 64):
                        self.send_error(409); return
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('a', encoding='utf-8') as stream:
                        stream.write(json.dumps(body, sort_keys=True) + '\n')
                        stream.flush(); os.fsync(stream.fileno())
                    entries.append(body)
                    result = {'accepted': True, 'event_id': body['event_id'], 'event_hash': body['event_hash']}
                elif self.path == '/entries' and identity == 'observer':
                    result = {'entries': entries}
                elif self.path == '/verify' and identity in ('substrate', 'observer'):
                    result = {'verified': body.get('event_id') == head['event_id'] and
                              body.get('event_hash') == head['event_hash'],
                              'event_id': head['event_id'], 'event_hash': head['event_hash']}
                else:
                    self.send_error(403); return
            payload = json.dumps(result).encode()
            self.send_response(200); self.send_header('Content-Length', str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
    server = ThreadingHTTPServer(('0.0.0.0', 8443), Handler)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain('/certs/server.crt', '/certs/server.key')
    context.load_verify_locations('/certs/ca.crt')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    serve_witness()
