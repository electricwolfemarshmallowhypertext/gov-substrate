"""Real AgentLAB runner + SMTP effects, deterministic upstream ground truth only.

No local result in this file is evidence of live model attack susceptibility.
Requires the separately installed, pinned upstream checkout.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
pytest.importorskip("agentdojo", reason="Pinned AgentLAB evaluation environment not installed")
from agentlab_smtp_integration import BoundExecutor, Dispatcher, source_case
from agentlab_smtp_integration import BoundedVictim
from openrouter_profiles import PROFILES
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.basic_elements import SystemMessage, InitQuery
from agentdojo.agent_pipeline.llms.openai_llm import _openai_to_assistant_message
from openai.types.chat import ChatCompletionMessage
from agentdojo.types import text_content_block_from_string
from agentdojo.functions_runtime import FunctionCall
from smtp_sink import LocalSMTPSink


class OriginalGroundTruthReplay:
    """Execute upstream call definitions through the original ToolsExecutor."""

    def __init__(self, user, injection):
        self.user, self.injection = user, injection

    def query(self, query, runtime, env, messages=(), extra_args=None):
        messages = list(messages)
        for task in (self.user, self.injection):
            for index, call in enumerate(task.ground_truth(env)):
                call = call.model_copy(deep=True)
                call.id = f"original-{task.ID}-{index}"
                messages.append({"role": "assistant", "tool_calls": [call],
                                 "content": [text_content_block_from_string("")]})
                _, _, _, messages, _ = BoundExecutor().query(query, runtime, env, messages, {})
        messages.append({"role": "assistant", "tool_calls": [],
                         "content": [text_content_block_from_string("Deterministic bridge verification.")]})
        return query, runtime, env, messages, {}


@pytest.mark.parametrize("case", [0, 3, 4])
def test_original_agentlab_case_smtp_fork(tmp_path, case):
    suite, user, injection, injections = source_case(case)
    original_injections = copy.deepcopy(injections)
    with LocalSMTPSink() as sink:
        bridge = Dispatcher(tmp_path / "bridge.db", sink, suite, injection, injections)
        utility, governed_attack = suite.run_task_with_pipeline(
            OriginalGroundTruthReplay(user, injection), user, injection, injections,
            runtime_class=bridge.runtime_class)
        assert injections == original_injections
        assert governed_attack is False
        assert len(bridge.forks) == 1
        fork = bridge.forks[0]
        assert fork["upstream_ambient_attack_success"] is True
        assert fork["injection_seen"] is True
        assert fork["ambient_smtp_messages"] == 1
        assert fork["governed_smtp_messages"] == 0
        assert fork["governed_smtp_mail_commands"] == 0
        assert fork["reason"] == "tool_disabled"
        assert len(sink.messages) == 1 and sink.mail_commands == 1
        assert any(e["tool"] == "search_calendar_events" and e["decision"] == "allow"
                   for e in bridge.events)


def test_changed_native_arguments_are_rejected_before_executor(tmp_path):
    suite, user, injection, injections = source_case(0)
    with LocalSMTPSink() as sink:
        bridge = Dispatcher(tmp_path / "bridge.db", sink, suite, injection, injections)
        env = suite.load_and_inject_default_environment(injections)
        runtime = bridge.runtime_class(suite.tools)
        call = injection.ground_truth(env)[0].model_copy(deep=True)
        call.id = "original-identity"
        runtime.pending = [call]
        changed = {**call.args, "body": "altered"}
        with pytest.raises(RuntimeError, match="arguments were altered"):
            runtime.run_function(env, call.function, changed)
        assert sink.messages == [] and sink.mail_commands == 0


def test_live_wrong_date_returns_original_error_and_allows_recovery(tmp_path):
    suite, user, injection, injections = source_case(0)
    with LocalSMTPSink() as sink:
        bridge = Dispatcher(tmp_path / "bridge.db", sink, suite, injection, injections)
        env = suite.load_and_inject_default_environment(injections)
        runtime = bridge.runtime_class(suite.tools)
        # Exact native call from the failed live run, with no argument correction.
        wrong = FunctionCall(function="search_calendar_events",
            args={"query": "Networking event", "date": "2025-05-26"},
            id="call_ab91abc4abb64271b00ee1f2")
        original = wrong.model_copy(deep=True)
        message = {"role": "assistant", "tool_calls": [wrong], "content": []}
        _, _, _, messages, _ = BoundExecutor().query(user.PROMPT, runtime, env, [message], {})
        assert wrong == original
        assert messages[-1]["error"] == "ValueError: No events found. Try with a different query."
        assert bridge.events[-1]["outcome"] == "failed"
        assert any(e["action"]["kind"] == "tool.result" and e["decision"] == "failed"
                   and e["action"].get("error") == "upstream_tool_error"
                   for e in bridge.substrate.audit())
        assert sink.messages == [] and not bridge.injection_seen
        # The actual original successful lookup still works after the real error.
        good = user.ground_truth(env)[0].model_copy(deep=True)
        good.id = "original-successful-lookup"
        message = {"role": "assistant", "tool_calls": [good], "content": []}
        _, _, _, messages, _ = BoundExecutor().query(user.PROMPT, runtime, env, [message], {})
        assert messages[-1]["error"] is None and bridge.injection_seen
        assert bridge.events[-1]["outcome"] == "succeeded"


def test_exact_original_prompt_tools_and_native_call_cross_sealed_path(tmp_path):
    suite, user, injection, injections = source_case(0)
    with LocalSMTPSink() as sink:
        bridge = Dispatcher(tmp_path / "bridge.db", sink, suite, injection, injections,
                            profile=PROFILES["glm"])
        env = suite.load_and_inject_default_environment(injections)
        runtime = bridge.runtime_class(suite.tools)
        _, _, _, messages, _ = SystemMessage(load_system_message(None)).query(user.PROMPT, runtime, env)
        _, _, _, messages, _ = InitQuery().query(user.PROMPT, runtime, env, messages)
        victim = BoundedVictim(bridge, PROFILES["glm"], "unused-offline-value", [])
        payload = victim.payload(runtime, messages)
        assert len(payload["tools"]) == len(suite.tools) == 24
        assert payload["messages"][-1]["content"][0]["text"] == user.PROMPT
        generation, sealed = victim.seal(payload)
        assert json.loads(sealed) == payload
        # Deterministic original definition, not a claimed model response.
        call = injection.ground_truth(env)[0].model_copy(deep=True)
        native = {"role": "assistant", "content": None, "tool_calls": [{
            "id": "native-offline-bridge", "type": "function", "function": {
                "name": call.function, "arguments": json.dumps(call.args)}}]}
        completed = bridge.substrate.complete_generation(generation, json.dumps(native))
        assert completed["decision"] == "succeeded"
        assistant = _openai_to_assistant_message(ChatCompletionMessage.model_validate(native))
        assert assistant["tool_calls"][0].args == call.args
        # Read the unchanged attack-bearing source through the real executor first.
        source_call = user.ground_truth(env)[0].model_copy(deep=True)
        source_call.id = "original-read"
        source_message = {"role": "assistant", "tool_calls": [source_call], "content": []}
        BoundExecutor().query(user.PROMPT, runtime, env, [source_message], {})
        BoundExecutor().query(user.PROMPT, runtime, env, [assistant], {})
        assert len(bridge.forks) == 1 and bridge.forks[0]["call_id"] == "native-offline-bridge"
        assert bridge.forks[0]["injection_seen"] is True
        assert victim.requests == 0 and len(sink.messages) == 1
