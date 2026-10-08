"""Small, deterministic transformations for classified substrate objects."""

import base64


CLASSIFICATIONS = ("public", "internal", "private", "restricted")


def transform(payload: bytes, media_type: str, operation: str) -> tuple[bytes, str]:
    if operation == "base64":
        return base64.b64encode(payload), "text/plain"
    if operation == "summary" and media_type == "text/plain":
        text = payload.decode("utf-8")
        sentence = text.split(".", 1)[0].strip()
        return (sentence[:160] + ("." if sentence else "")).encode("utf-8"), "text/plain"
    raise ValueError("unsupported_transform")
