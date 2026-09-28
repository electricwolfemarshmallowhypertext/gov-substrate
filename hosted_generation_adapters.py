"""Text-only hosted providers for sealed, one-use generation manifests.

API clients and their credentials belong to the trusted host application.
"""

from dataclasses import dataclass

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

    def __post_init__(self):
        if not self.model or self.max_output_tokens <= 0 or self.max_context_bytes <= 0:
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

    def __post_init__(self):
        if not self.model or self.max_output_tokens <= 0 or self.max_context_bytes <= 0:
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
