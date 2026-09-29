"""Text-only hosted providers for sealed, one-use generation manifests.

API clients and their credentials belong to the trusted host application.
"""

from dataclasses import dataclass
import json
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
