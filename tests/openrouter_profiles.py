"""Pinned OpenRouter routes shared by hosted validation and the authority challenge."""

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class ValidationProfile:
    model: str
    upstream: str
    zdr: bool
    retention: str
    input_rate: Decimal
    output_rate: Decimal


PROFILES = {
    "glm": ValidationProfile(
        "z-ai/glm-5.2", "z-ai", True, "zero retention",
        Decimal("1.40"), Decimal("4.40")),
    "grok": ValidationProfile(
        "x-ai/grok-4.7", "xai", False, "30 days",
        Decimal("2.00"), Decimal("6.00")),
    "kimi": ValidationProfile(
        "moonshotai/kimi-k3", "moonshotai", True, "zero retention",
        Decimal("3.00"), Decimal("15.00")),
}
