"""Deterministic OpenShell control tests; no gateway is required."""

import json
from types import SimpleNamespace

import pytest

from openshell_runtime_supervisor import OpenShellRuntimeSupervisor


def supervisor(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    return OpenShellRuntimeSupervisor(
        "gov-substrate-runtime-probe:test", policy, "testproject", "testgateway"
    )


def item(generation_id, owner="testproject"):
    return {
        "id": f"sandbox-{generation_id}",
        "name": f"gs-{generation_id[:16]}",
        "phase": "Ready",
        "labels": {
            "gov.substrate.managed": "true",
            "gov.substrate.generation_id": generation_id,
            "gov.substrate.owner": owner,
        },
    }


def test_create_command_seals_identity_policy_and_environment(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "a" * 32
    command = runtime._create_command(generation_id)

    assert command[:5] == ["openshell", "--gateway", "testgateway", "--color", "never"]
    assert ["--name", "gs-" + "a" * 16] == command[command.index("--name"):command.index("--name") + 2]
    assert "--no-auto-providers" in command and "--no-keep" in command
    assert "gov.substrate.generation_id=" + generation_id in command
    assert command[-2:] == [
        "gov-runtime-probe", f"/tmp/gov-input-{generation_id}/input.json",
    ]


def test_identity_requires_exact_full_generation_labels(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "b" * 32
    runtime._list = lambda _selector: [item(generation_id)]
    assert runtime.runtime_identity(generation_id) == f"sandbox-{generation_id}"

    bad = item(generation_id)
    bad["labels"]["gov.substrate.owner"] = "other"
    runtime._list = lambda _selector: [bad]
    with pytest.raises(RuntimeError, match="identity mismatch"):
        runtime.runtime_identity(generation_id)


def test_stop_deletes_exact_sandbox_and_verifies_absence(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "c" * 32
    state = [item(generation_id)]
    commands = []
    runtime._list = lambda _selector: list(state)

    def command(*args, timeout=30):
        commands.append(args)
        if args[:2] == ("sandbox", "delete"):
            state.clear()
        return ""

    runtime._openshell = command
    result = runtime.stop((generation_id,))[0]
    assert result.confirmed and result.runtime_id == f"sandbox-{generation_id}"
    assert result.runtime == "openshell" and result.state == "stopped"
    assert commands == [("sandbox", "delete", "gs-" + "c" * 16)]


def test_reconcile_deletes_only_owned_managed_sandboxes(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "d" * 32
    state = [item(generation_id)]
    runtime._list = lambda selector: list(state)
    runtime._openshell = lambda *args, **_kwargs: state.clear() or ""

    results = runtime.reconcile()
    assert len(results) == 1 and results[0].confirmed


def test_control_failure_never_reports_confirmed_shutdown(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "e" * 32
    runtime._list = lambda _selector: [item(generation_id)]
    runtime._openshell = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("gateway unavailable")
    )
    result = runtime.stop((generation_id,))[0]
    assert not result.confirmed and result.state == "stop_unconfirmed"


def test_list_parser_accepts_collection_and_rejects_other_shapes(tmp_path):
    runtime = supervisor(tmp_path)
    assert runtime._items(json.dumps([item("f" * 32)]))[0]["id"].startswith("sandbox-")
    assert runtime._items(json.dumps({"next_page_token": "", "sandboxes": []})) == []
    with pytest.raises(RuntimeError, match="unexpected OpenShell list response"):
        runtime._items("{}")
