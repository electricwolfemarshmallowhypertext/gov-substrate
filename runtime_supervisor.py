"""Runtime-neutral control of substrate-owned generation workers."""

from dataclasses import asdict, dataclass
from typing import Protocol


@dataclass(frozen=True)
class StopResult:
    generation_id: str
    runtime: str
    runtime_id: str | None
    confirmed: bool
    state: str

    def audit(self) -> dict:
        return asdict(self)


class RuntimeSupervisor(Protocol):
    def run(self, generation_id: str, sealed_context: str) -> str: ...

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]: ...

    def reconcile(self) -> tuple[StopResult, ...]: ...
