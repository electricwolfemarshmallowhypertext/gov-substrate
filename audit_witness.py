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
