"""Backend-neutral fixtures required by the real runtime conformance suite."""

from dataclasses import dataclass
from typing import Protocol

from .runtime_supervisor import RuntimeSupervisor


@dataclass(frozen=True)
class RuntimeIdentity:
    runtime_id: str
    running: bool


@dataclass(frozen=True)
class ReachableTarget:
    address: str
    gateway: str


class RuntimeConformanceBackend(Protocol):
    """Real backend operations used by the shared conformance assertions."""

    name: str
    probe_target: str
    granted_attempts: set[str]
    supervisor: RuntimeSupervisor

    def new_supervisor(self) -> RuntimeSupervisor: ...

    def wait_running(self, generation_id: str) -> RuntimeIdentity: ...

    def launch_orphan(self, generation_id: str,
                      sealed_context: str) -> RuntimeIdentity: ...

    def assert_terminated(self, runtime_id: str) -> None: ...

    def start_reachable_target(self) -> ReachableTarget: ...

    def cleanup(self) -> None: ...
