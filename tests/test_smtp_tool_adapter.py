"""Real loopback SMTP effects through the substrate; no provider/model calls."""

import base64
import copy
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from governance_substrate.substrate import Substrate, digest
from governance_substrate.tool_adapter import SMTPSendEmailAdapter
sys.path.insert(0, str(Path(__file__).resolve().parent))
from smtp_sink import LocalSMTPSink


def boundary(tmp_path, sink, *, granted=True, installed=True):
    adapter = SMTPSendEmailAdapter("127.0.0.1", sink.port, "operator@example.test")
    actor = {"network": {"allowed": False}, "filesystem": {"read": False, "write": False},
             "tools": {"send_email": granted}, "persistence": {"session": True,
             "cross_session": False}, "shared_channels": [], "data": {"sensitive_access": False}}
    substrate = Substrate(tmp_path / "tools.db", {
        "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
        "operator_token": "operator", "circuit_operator_token": "control"},
        tool_adapters={"send_email": adapter} if installed else {})
    session = substrate.create_session("agent")["session_token"]
    return substrate, session, adapter


def action():
    return {"kind": "tool.invoke", "tool": "send_email", "call_id": "native-call-1",
            "arguments": {"recipients": ["recipient@example.test"],
                          "subject": "Local delivery", "body": "Observable SMTP content",
                          "cc": ["copy@example.test"], "bcc": ["blind@example.test"]}}


def test_granted_tool_delivers_and_records_separate_outcome(tmp_path):
    with LocalSMTPSink() as sink:
        substrate, session, _ = boundary(tmp_path, sink)
        request = action()
        original = copy.deepcopy(request)
        grant = substrate.propose("agent", session, request, authorize_only=True)
        assert sink.mail_commands == 0
        result = substrate.propose("agent", session, request, grant["execution_token"])
        assert result["outcome"] == "succeeded"
        assert request == original
        assert sink.mail_commands == 1 and len(sink.messages) == 1
        received = BytesParser(policy=policy.default).parsebytes(sink.messages[0]["data"])
        assert received["Subject"] == request["arguments"]["subject"]
        assert received.get_content().strip() == request["arguments"]["body"]
        assert sink.messages[0]["recipients"] == ["recipient@example.test", "copy@example.test",
                                                "blind@example.test"]
        assert received["Bcc"] is None
        audit = substrate.audit()
        event = next(e for e in audit if e["id"] == result["event_id"])
        assert event["action"]["arguments_sha256"] == digest(request["arguments"])
        assert event["action"]["call_id"] == request["call_id"]
        assert any(e["id"] == result["outcome_event_id"] and
                   e["action"]["kind"] == "tool.result" and e["decision"] == "succeeded"
                   for e in audit)
        replay = substrate.propose("agent", session, request, grant["execution_token"])
        assert replay["reason"] == "execution_grant_reused"
        assert len(sink.messages) == 1


@pytest.mark.parametrize("granted,installed,reason", [
    (False, True, "tool_disabled"), (True, False, "tool_adapter_absent")])
def test_denied_or_unimplemented_tool_never_contacts_smtp(tmp_path, granted, installed, reason):
    with LocalSMTPSink() as sink:
        substrate, session, _ = boundary(tmp_path, sink, granted=granted, installed=installed)
        result = substrate.propose("agent", session, action())
        assert result["decision"] == "deny" and result["reason"] == reason
        assert sink.mail_commands == 0 and sink.messages == []
        assert any(e["id"] == result["event_id"] and e["decision"] == "deny"
                   for e in substrate.audit())


def test_altered_grant_and_circuit_revocation_prevent_smtp(tmp_path):
    with LocalSMTPSink() as sink:
        substrate, session, _ = boundary(tmp_path, sink)
        request = action()
        grant = substrate.propose("agent", session, request, authorize_only=True)
        altered = copy.deepcopy(request)
        altered["arguments"]["body"] = "Changed after approval"
        assert substrate.propose("agent", session, altered, grant["execution_token"])[
            "reason"] == "execution_grant_binding_mismatch"
        substrate.set_circuit("control", "capability", "tool", True, "Stop mail execution")
        assert substrate.propose("agent", session, request, grant["execution_token"])[
            "decision"] == "deny"
        assert sink.mail_commands == 0 and sink.messages == []


def test_sensitive_read_cannot_escape_through_enabled_mail_tool(tmp_path):
    with LocalSMTPSink() as sink:
        substrate, session, _ = boundary(tmp_path, sink)
        obj = substrate.import_object("private", "text/plain",
              base64.b64encode(b"protected local test input").decode(), ["agent"], "test")
        substrate.propose("agent", session, {"kind": "object.read", "object_id": obj["object_id"]})
        result = substrate.propose("agent", session, action())
        assert result["reason"] == "sensitive_external_egress_disabled"
        assert sink.mail_commands == 0


def test_agent_cannot_override_smtp_connection_settings(tmp_path):
    with LocalSMTPSink() as sink:
        substrate, session, _ = boundary(tmp_path, sink)
        request = action()
        request["arguments"]["host"] = "unapproved.example"
        assert substrate.propose("agent", session, request)["reason"] == "invalid_tool_arguments"
        assert sink.mail_commands == 0
