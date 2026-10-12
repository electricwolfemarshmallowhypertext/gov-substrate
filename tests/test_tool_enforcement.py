"""Real process -> HTTP substrate -> SMTP executor; no model or mocked transport."""

import copy
import json
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path

import uvicorn

from governance_substrate.substrate import Substrate, create_app, digest
from governance_substrate.tool_adapter import SMTPSendEmailAdapter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from smtp_sink import LocalSMTPSink


CLIENT = """
import json, sys
from urllib.request import Request, build_opener, ProxyHandler
config = json.load(sys.stdin)
opener = build_opener(ProxyHandler({}))
def post(path, body, session=None):
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer ' + config['token']}
    if session:
        headers['X-Session-Token'] = session
    request = Request(config['url'] + path, data=json.dumps(body).encode(),
                      headers=headers, method='POST')
    with opener.open(request, timeout=10) as response:
        return json.load(response)
session = post('/sessions', {})['session_token']
print(json.dumps(post('/proposals', {'action': config['action']}, session)))
"""


def run_real_tool_enforcement(action=None, *, model_generated=False):
    proof_name = "live-tool-enforcement-proof" if model_generated else "tool-enforcement-proof"
    directory = ROOT / "dist" / proof_name / uuid.uuid4().hex
    directory.mkdir(parents=True)
    action = action if action is not None else {"kind": "tool.invoke", "tool": "send_email", "call_id": uuid.uuid4().hex,
              "arguments": {"recipients": ["recipient@example.test"],
                            "subject": "Real executor boundary proof",
                            "body": "Disposable local SMTP effect."}}
    tokens = {actor: secrets.token_hex(32) for actor in ("allowed", "denied")}
    actors = {}
    for actor in tokens:
        actors[actor] = {
            "network": {"allowed": False}, "filesystem": {"read": False, "write": False},
            "tools": {"send_email": actor == "allowed"},
            "persistence": {"session": True, "cross_session": False},
            "shared_channels": [], "data": {"sensitive_access": False}}
    with LocalSMTPSink() as sink:
        adapter = SMTPSendEmailAdapter("127.0.0.1", sink.port, "operator@example.test")
        substrate = Substrate(directory / "substrate.db", {
            "actors": actors, "tokens": {token: actor for actor, token in tokens.items()},
            "operator_token": secrets.token_hex(32)}, tool_adapters={"send_email": adapter})
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(create_app(substrate), log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                assert thread.is_alive() and time.monotonic() < deadline, "HTTP server did not start"
                time.sleep(0.01)

            def submit(actor):
                result = subprocess.run([sys.executable, "-c", CLIENT],
                    input=json.dumps({"url": url, "token": tokens[actor], "action": action}),
                    text=True, capture_output=True, timeout=15, check=True)
                return json.loads(result.stdout)

            allowed = submit("allowed")
            if allowed.get("decision") != "allow" or allowed.get("outcome") != "succeeded":
                failure = {"result": "FAIL", "stage": "authorized_control",
                    "request_sha256": digest(action), "response": allowed,
                    "smtp_messages": len(sink.messages), "smtp_mail_commands": sink.mail_commands,
                    "audit": substrate.audit()}
                (directory / "failure.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
                raise RuntimeError("authorized_control_failed:" + allowed.get("reason", "unknown"))
            assert len(sink.messages) == 1 and sink.mail_commands == 1
            message = BytesParser(policy=policy.default).parsebytes(sink.messages[0]["data"])
            assert message["Subject"] == action["arguments"]["subject"]
            assert message.get_content().strip() == action["arguments"]["body"]
            assert sink.messages[0]["recipients"] == action["arguments"]["recipients"]
            before_messages = copy.deepcopy(sink.messages)
            before_commands = sink.mail_commands
            denied = submit("denied")
            assert denied["decision"] == "deny" and denied["reason"] == "tool_disabled"
            assert sink.messages == before_messages and sink.mail_commands == before_commands
            event = next(e for e in substrate.audit() if e["id"] == denied["event_id"])
            assert event["actor"] == "denied" and event["decision"] == "deny"
            assert event["action"]["call_id"] == action["call_id"]
            assert event["action"]["arguments_sha256"] == digest(action["arguments"])
            receipt = {"result": "PASS", "evidence_kind": "real_HTTP_SMTP_executor_enforcement",
                "model_generated": model_generated, "isolated_worker_proof": False,
                "request_sha256": digest(action), "allowed_smtp_messages": 1,
                "denied_additional_smtp_messages": len(sink.messages) - len(before_messages),
                "denied_additional_smtp_mail_commands": sink.mail_commands - before_commands,
                "denial": denied, "audit_receipt": event}
            path = directory / "receipt.json"
            path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            print(json.dumps({"result": "PASS", "allowed_smtp_messages": 1,
                "denied_additional_smtp_messages": 0, "denied_additional_smtp_mail_commands": 0,
                "denial_event_id": denied["event_id"], "receipt": str(path),
                "model_generated": model_generated, "isolated_worker_proof": False}))
            return {**receipt, "receipt": str(path)}
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
            assert not thread.is_alive(), "HTTP server cleanup failed"


def test_real_process_request_is_denied_before_smtp_and_audited():
    run_real_tool_enforcement()
