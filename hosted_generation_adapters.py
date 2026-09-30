"""Text-only hosted providers for sealed, one-use generation manifests.

API clients and their credentials belong to the trusted host application.
"""

from dataclasses import dataclass
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from generation_adapter import SealedInput


def _governed_text(inputs: tuple[SealedInput, ...], max_context_bytes: int) -> tuple[str, ...]:
    if not inputs or sum(len(source.content) for source in inputs) > max_context_bytes:
        raise RuntimeError("Sealed text context is empty or exceeds the configured limit")
    if any(source.media_type != "text/plain" for source in inputs):
        raise RuntimeError("Hosted text adapter accepts governed text only")
    try:
        return tuple(source.content.decode("utf-8") for source in inputs)
    except UnicodeDecodeError:
        raise RuntimeError("Sealed text context is not UTF-8") from None


@dataclass(frozen=True)
class OpenAITextAdapter:
    client: object
    model: str
    max_output_tokens: int
    max_context_bytes: int = 32_768
    service_id: str = "openai"

    def __post_init__(self):
        if (not self.model or self.max_output_tokens <= 0 or
                self.max_context_bytes <= 0 or not self.service_id):
            raise ValueError("Model and positive request limits are required")

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        texts = _governed_text(inputs, self.max_context_bytes)
        try:
            response = self.client.with_options(max_retries=0).responses.create(
                model=self.model,
                input=[{"role": "user", "content": [
                    {"type": "input_text", "text": text} for text in texts]}],
                max_output_tokens=self.max_output_tokens,
                truncation="disabled",
                store=False)
        except Exception as exc:
            raise RuntimeError(f"OpenAI request failed: {type(exc).__name__}") from None
        if response.status != "completed":
            raise RuntimeError("OpenAI response did not complete")
        for item in response.output:
            if item.type not in ("reasoning", "message"):
                raise RuntimeError("OpenAI response included an unexpected action")
            if item.type == "message" and any(
                    block.type != "output_text" for block in item.content):
                raise RuntimeError("OpenAI response included non-text content")
        if type(response.output_text) is not str or not response.output_text.strip():
            raise RuntimeError("OpenAI response contained no text")
        return response.output_text


@dataclass(frozen=True)
class AnthropicTextAdapter:
    client: object
    model: str
    max_output_tokens: int
    max_context_bytes: int = 32_768
    service_id: str = "anthropic"

    def __post_init__(self):
        if (not self.model or self.max_output_tokens <= 0 or
                self.max_context_bytes <= 0 or not self.service_id):
            raise ValueError("Model and positive request limits are required")

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        texts = _governed_text(inputs, self.max_context_bytes)
        try:
            response = self.client.with_options(max_retries=0).messages.create(
                model=self.model,
                max_tokens=self.max_output_tokens,
                messages=[{"role": "user", "content": [
                    {"type": "text", "text": text} for text in texts]}])
        except Exception as exc:
            raise RuntimeError(f"Anthropic request failed: {type(exc).__name__}") from None
        if response.stop_reason != "end_turn" or not response.content:
            raise RuntimeError("Anthropic response did not complete as text")
        if any(block.type != "text" for block in response.content):
            raise RuntimeError("Anthropic response included non-text content")
        text = "".join(block.text for block in response.content)
        if not text.strip():
            raise RuntimeError("Anthropic response contained no text")
        return text


class GeminiHTTPError(RuntimeError):
    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"Gemini API returned HTTP {status_code}")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class GeminiDeveloperClient:
    """One direct Gemini Developer API request; credentials stay on the host."""

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("Gemini API key is required")
        self._api_key = api_key
        self._opener = build_opener(_NoRedirect)

    def generate_content(self, model: str, contents: list, config: dict) -> dict:
        if not model or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-." for char in model):
            raise ValueError("Invalid Gemini model ID")
        request = Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            data=json.dumps({"contents": contents, "generationConfig": config}).encode(),
            headers={"Content-Type": "application/json", "x-goog-api-key": self._api_key},
            method="POST")
        try:
            with self._opener.open(request, timeout=45) as response:
                return json.load(response)
        except HTTPError as exc:
            raise GeminiHTTPError(exc.code) from None
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"Gemini API transport failed: {type(exc).__name__}") from None


@dataclass
class GeminiTextAdapter:
    client: object
    model: str
    max_output_tokens: int
    max_context_bytes: int = 32_768
    service_id: str = "google-gemini"
    last_usage: dict | None = None

    def __post_init__(self):
        if (not self.model or self.max_output_tokens <= 0 or
                self.max_context_bytes <= 0 or not self.service_id):
            raise ValueError("Model and positive request limits are required")

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        texts = _governed_text(inputs, self.max_context_bytes)
        try:
            response = self.client.generate_content(
                model=self.model,
                contents=[{"role": "user", "parts": [{"text": text} for text in texts]}],
                config={"candidateCount": 1, "maxOutputTokens": self.max_output_tokens,
                        "thinkingConfig": {"thinkingLevel": "low"}})
        except GeminiHTTPError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Gemini request failed: {type(exc).__name__}") from None
        self.last_usage = response.get("usageMetadata") if type(response) is dict else None
        candidates = response.get("candidates") if type(response) is dict else None
        if type(candidates) is not list or len(candidates) != 1:
            raise RuntimeError("Gemini response did not contain one candidate")
        candidate = candidates[0]
        if type(candidate) is not dict or candidate.get("finishReason") != "STOP":
            raise RuntimeError("Gemini response did not finish normally")
        content = candidate.get("content")
        parts = content.get("parts") if type(content) is dict else None
        if type(parts) is not list or not parts:
            raise RuntimeError("Gemini response contained no text")
        output = []
        for part in parts:
            if (type(part) is not dict or
                    set(part) - {"text", "thought", "thoughtSignature"} or
                    type(part.get("text")) is not str):
                raise RuntimeError("Gemini response included non-text content")
            if not part.get("thought", False):
                output.append(part["text"])
        text = "".join(output)
        if not text.strip():
            raise RuntimeError("Gemini response contained no text")
        return text


def _redact_error_text(value: str) -> str:
    value = re.sub(r"(?i)bearer\s+[^\s,;]+", "Bearer [REDACTED]", value)
    return re.sub(r"sk-or-[A-Za-z0-9_-]+", "[REDACTED]", value)[:1000]


def _sanitize_error_metadata(value, depth=0):
    blocked = {"authorization", "headers", "api_key", "key", "prompt",
               "messages", "content", "input", "output", "request", "body"}
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(key): _sanitize_error_metadata(item, depth + 1)
                for key, item in value.items()
                if str(key).lower() not in blocked}
    if isinstance(value, list):
        return [_sanitize_error_metadata(item, depth + 1) for item in value[:20]]
    if isinstance(value, str):
        return _redact_error_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[REDACTED]"


class OpenRouterHTTPError(RuntimeError):
    def __init__(self, status_code: int, message="", code=None,
                 error_type=None, metadata=None):
        self.status_code = status_code
        self.message = _redact_error_text(str(message))
        self.code = code if isinstance(code, (str, int, float)) else None
        self.error_type = (error_type if isinstance(error_type, str) else None)
        self.metadata = _sanitize_error_metadata(metadata or {})
        super().__init__(f"OpenRouter API returned HTTP {status_code}")


class OpenRouterResponseError(RuntimeError):
    def __init__(self, reason: str, metadata=None):
        self.reason = reason
        self.metadata = _sanitize_error_metadata(metadata or {})
        super().__init__(f"OpenRouter response rejected: {reason}")


class OpenRouterClient:
    """One direct OpenRouter request with a single pinned upstream provider."""

    def __init__(self, api_key: str, upstream_provider: str, zdr: bool = True):
        if not api_key or not upstream_provider:
            raise ValueError("OpenRouter key and upstream provider are required")
        self._api_key = api_key
        self.upstream_provider = upstream_provider
        self.zdr = zdr
        self._opener = build_opener(_NoRedirect)

    def chat_completion(self, model: str, messages: list,
                        max_completion_tokens: int) -> dict:
        allowed = "abcdefghijklmnopqrstuvwxyz0123456789-./_:"
        if not model or any(char not in allowed for char in model):
            raise ValueError("Invalid OpenRouter model ID")
        body = {
            "model": model,
            "messages": messages,
            "max_completion_tokens": max_completion_tokens,
            "stream": False,
            "provider": {
                "only": [self.upstream_provider],
                "allow_fallbacks": False,
                "data_collection": "deny",
                "zdr": self.zdr,
            },
        }
        request = Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._api_key}",
                     "X-OpenRouter-Metadata": "enabled"},
            method="POST")
        try:
            with self._opener.open(request, timeout=45) as response:
                return json.load(response)
        except HTTPError as exc:
            raise self._http_error(exc) from None
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(
                f"OpenRouter transport failed: {type(exc).__name__}") from None

    def current_key_status(self) -> dict:
        request = Request(
            "https://openrouter.ai/api/v1/key",
            headers={"Authorization": f"Bearer {self._api_key}"}, method="GET")
        try:
            with self._opener.open(request, timeout=15) as response:
                payload = json.load(response)
        except HTTPError as exc:
            raise self._http_error(exc) from None
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(
                f"OpenRouter key-status request failed: {type(exc).__name__}") from None
        data = payload.get("data") if type(payload) is dict else None
        if type(data) is not dict:
            raise RuntimeError("OpenRouter key-status response was malformed")
        limit = data.get("limit")
        remaining = data.get("limit_remaining")
        if limit is not None and not isinstance(limit, (int, float)):
            raise RuntimeError("OpenRouter key limit was malformed")
        if remaining is not None and not isinstance(remaining, (int, float)):
            raise RuntimeError("OpenRouter remaining key limit was malformed")
        return {"available": True, "spending_limit_configured": limit is not None,
                "limit_usd": limit, "limit_remaining_usd": remaining,
                "limit_reset": data.get("limit_reset")}

    @staticmethod
    def _http_error(exc: HTTPError) -> OpenRouterHTTPError:
        try:
            payload = json.loads(exc.read(65_536))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            payload = {}
        error = payload.get("error") if type(payload) is dict else None
        if type(error) is not dict:
            error = {}
        metadata = error.get("metadata")
        error_type = error.get("type")
        if error_type is None and type(metadata) is dict:
            error_type = metadata.get("type")
        return OpenRouterHTTPError(
            exc.code, message=error.get("message", ""), code=error.get("code"),
            error_type=error_type, metadata=metadata)


@dataclass
class OpenRouterTextAdapter:
    client: object
    model: str
    max_output_tokens: int
    max_context_bytes: int = 32_768
    service_id: str = "openrouter"
    last_usage: dict | None = None
    last_routing: dict | None = None

    def __post_init__(self):
        if (not self.model or self.max_output_tokens <= 0 or
                self.max_context_bytes <= 0 or not self.service_id):
            raise ValueError("Model and positive request limits are required")

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        texts = _governed_text(inputs, self.max_context_bytes)
        try:
            response = self.client.chat_completion(
                model=self.model,
                messages=[{"role": "user", "content": [
                    {"type": "text", "text": text} for text in texts]}],
                max_completion_tokens=self.max_output_tokens)
        except OpenRouterHTTPError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"OpenRouter request failed: {type(exc).__name__}") from None
        if type(response) is not dict:
            raise OpenRouterResponseError("malformed_response")
        if type(response.get("error")) is dict:
            error = response["error"]
            raise OpenRouterResponseError("error_payload_on_success", {
                "message": error.get("message"), "code": error.get("code"),
                "type": error.get("type"), "metadata": error.get("metadata")})
        if response.get("model") != self.model:
            raise OpenRouterResponseError("unexpected_model", {
                "requested_model": self.model,
                "returned_model": response.get("model")})
        self.last_usage = response.get("usage")
        self.last_routing = response.get("openrouter_metadata")
        self._verify_routing()
        choices = response.get("choices")
        if type(choices) is not list or len(choices) != 1:
            raise OpenRouterResponseError("unexpected_choice_count", {
                "choice_count": len(choices) if type(choices) is list else None})
        choice = choices[0]
        if type(choice) is not dict or choice.get("finish_reason") != "stop":
            raise OpenRouterResponseError("non_normal_finish", {
                "finish_reason": (choice.get("finish_reason")
                                  if type(choice) is dict else None)})
        message = choice.get("message")
        if (type(message) is not dict or message.get("tool_calls") or
                type(message.get("content")) is not str or
                not message["content"].strip()):
            raise OpenRouterResponseError("no_plain_text", {
                "message_present": type(message) is dict,
                "tool_calls_present": (bool(message.get("tool_calls"))
                                       if type(message) is dict else False),
                "content_type": (type(message.get("content")).__name__
                                 if type(message) is dict else None)})
        return message["content"]

    def _verify_routing(self):
        routing = self.last_routing
        endpoints = routing.get("endpoints") if type(routing) is dict else None
        available = endpoints.get("available") if type(endpoints) is dict else None
        selected = ([item for item in available if type(item) is dict and
                     item.get("selected") is True] if type(available) is list else [])
        expected = "".join(char for char in self.client.upstream_provider.lower()
                           if char.isalnum())
        actual = ("".join(char for char in selected[0].get("provider", "").lower()
                          if char.isalnum()) if len(selected) == 1 else "")
        if (type(routing) is not dict or routing.get("requested") != self.model or
                len(selected) != 1 or
                expected != actual):
            raise OpenRouterResponseError("pinned_upstream_not_confirmed", {
                "routing_present": type(routing) is dict,
                "requested_model": (routing.get("requested")
                                    if type(routing) is dict else None),
                "available_endpoint_count": (len(available)
                                             if type(available) is list else None),
                "selected_providers": [item.get("provider") for item in selected]})
