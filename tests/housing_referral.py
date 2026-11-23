"""Local H-001 acceptance fixture. Use real HTTP, SQLite and the production mTLS witness."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError

from acceptance.phase9.test_gateway_boundary import certificates
from deployed_authority_service import verify_event_chain
from governance_substrate.audit_witness import MTLSAuditWitness, serve_witness
from governance_substrate.substrate import Substrate
from real_enforcement_support import actor, real_api

ROOT = Path(__file__).resolve().parents[1]
MEMOS = {"A": "Close the case when the income field is missing.",
         "B": "Refer disputed income fields for human review."}
CASE = "H-001"
ROLES = ("lead", "analyst", "replacement", "registrar")


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def witness_client(port, certs, role):
    return MTLSAuditWitness(f"https://127.0.0.1:{port}", str(certs / "ca.crt"),
                            str(certs / f"{role}.crt"), str(certs / f"{role}.key"))


def verify(directory):
    events = json.loads((directory / "audit.json").read_bytes())
    entries = json.loads((directory / "witness.json").read_bytes())
    head = verify_event_chain(events)
    assert len(entries) == len(events) > 0
    for index, (row, event) in enumerate(zip(entries, events), 1):
        assert row == {"event_id": index, "event_hash": event["event_hash"],
                       "previous_hash": event["prev_hash"]}
        assert event["id"] == index
    assert json.loads((directory / "head.json").read_bytes()) == {
        "verified": True, "event_id": len(events), "event_hash": head}
    return head


def workflow(substrate, post, operator, control, reason):
    def task(role, parent=None, capabilities=("session", "state", "object")):
        return post("/tasks/issue", {"actor": role, "capabilities": capabilities,
                    "parent_id": parent, "ttl_seconds": 240 if parent else 900}, operator)

    def session(task_record):
        token = task_record["task_token"]
        return (token, post("/sessions", {}, token)["session_token"])

    def propose(credentials, action):
        return post("/proposals", {"action": action}, *credentials)

    def override(event, explanation):
        return post("/overrides", {"event_id": event["event_id"], "reason": explanation}, operator)

    def write(scope, key, value, **extra):
        return dict(kind="state.write", scope=scope, key=key, value=value, **extra)

    root = task("lead")
    child = task("analyst", root["task_id"])
    analyst = session(child)
    lead = session(root)
    registrar = session(task("registrar"))
    try:
        task("replacement", root["task_id"], ("session", "network"))
    except HTTPError as error:
        assert error.code == 400
    else:
        raise AssertionError("child task exceeded parent capability categories")

    def exhibit(name, content, readers):
        return post("/objects/import", {"classification": "private", "media_type": "text/plain",
                    "content_base64": base64.b64encode(content.encode()).decode(),
                    "readers": readers, "source": name}, operator)["object_id"]

    sources = {}
    for name, memo in MEMOS.items():
        oid = exhibit("synthetic-memo-" + name, memo, ["lead", "analyst", "replacement"])
        read = {"kind": "object.read", "object_id": oid}
        for credentials in (lead, analyst):
            assert base64.b64decode(propose(credentials, read)["content_base64"]) == memo.encode()
        sources[name] = {"object_id": oid, "sha256": hashlib.sha256(memo.encode()).hexdigest()}
    sealed = exhibit("lead-only", "Restricted exhibit", ["lead"])
    read = {"kind": "object.read", "object_id": sealed}
    assert propose(lead, read)["decision"] == "allow"
    assert propose(analyst, read)["reason"] == "object_not_accessible"

    disposition = write("shared", CASE, "closed", channel="dispositions")
    denied = propose(analyst, disposition)
    assert denied["reason"] == "shared_channel_disabled"
    assert override(denied, reason)["reason"] == "target_not_escalated"
    assert propose(registrar, {**disposition, "key": "positive-control"})["decision"] == "allow"

    referral = {"status": "refer for human review", "income": "missing and disputed",
                "policy": "fixture-v1", "sources": sources}
    request = propose(analyst, write("persistent", CASE, referral))
    assert request["decision"] == "escalate"
    approved = override(request, reason)
    assert approved["override_of"] == request["event_id"]
    assert override(request, reason)["reason"] == "already_overridden"
    pending = propose(analyst, write("persistent", "obsolete-note", CASE))
    assert pending["decision"] == "escalate"
    note = write("session", CASE, "review continues")
    stale = post("/authorizations", {"action": note}, *analyst)["execution_token"]
    stop = substrate.set_circuit(control, "actor", "lead", True, "H-001: transfer assignment")
    assert stop["shutdown_confirmed"]
    assert override(pending, reason)["reason"] == "origin_authority_revoked"
    try:
        post("/sessions", {}, child["task_token"])
    except HTTPError as error:
        assert error.code == 401
    else:
        raise AssertionError("withdrawn task authenticated")
    successor = session(task("replacement"))
    assert propose((successor[0], analyst[1]), note)["reason"] == "invalid_session"
    def execute(token):
        return post("/executions", {"action": note, "execution_token": token}, *successor)
    assert execute(stale)["decision"] == "deny"
    for source in sources.values():
        assert propose(successor, {"kind": "object.read", "object_id": source["object_id"]})["decision"] == "allow"
    grant = post("/authorizations", {"action": note}, *successor)["execution_token"]
    assert execute(grant)["decision"] == "allow"
    assert execute(grant)["reason"] == "execution_grant_reused"
    assert propose(registrar, {"kind": "state.read", "scope": "shared", "key": "positive-control",
                               "channel": "dispositions"})["value"] == "closed"

    events = substrate.audit()
    revocations = events[stop["receipt_event_id"] - 1]["action"]["receipt"]["what"]["revoked"]
    assert (revocations["execution_grants"], revocations["sessions"], revocations["task_identities"]) == (1, 2, 2)
    with sqlite3.connect(Path(substrate.db_path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("SELECT namespace,key,value FROM state ORDER BY namespace,key").fetchall()
        status = db.execute("SELECT status FROM execution_grants WHERE token_hash=?",
                            (hashlib.sha256(stale.encode()).hexdigest(),)).fetchone()
        assert status == ("revoked",)
    assert len(rows) == 3
    expected = {("persistent:analyst", CASE): referral, ("shared:dispositions", "positive-control"): "closed"}
    for namespace, key, value in rows:
        if namespace.startswith("session:") and namespace.endswith(":replacement"):
            assert key == CASE and json.loads(value) == "review continues"
        else:
            assert json.loads(value) == expected.pop((namespace, key))
    assert not expected
    assert all(row["key"] != "obsolete-note" and (row["namespace"], row["key"]) !=
               ("shared:dispositions", CASE) for e in events for row in e["state_after"]["state"])
    assert sum(e["decision"] == "override" for e in events) == 1
    return events, {"revocations": revocations, "final_state": rows, "approved_event": approved["event_id"],
                    "stale_approval_event": pending["event_id"], "review_reason": reason,
                    "denied_disposition_event": denied["event_id"], "sources": sources}


def run(reason):
    directory = ROOT / "dist" / "housing-review" / secrets.token_hex(8)
    directory.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        certs = Path(tmp) / "certs"
        certificates(certs, client_names=("substrate", "observer"))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "WITNESS_PATH": str(directory / "journal.jsonl")}
        proc = subprocess.Popen([sys.executable, __file__, "--witness", str(port), str(certs)], env=env)
        try:
            witness = witness_client(port, certs, "substrate")
            for _ in range(100):
                try:
                    if witness.verify(0, "0" * 64):
                        break
                except RuntimeError:
                    pass
                assert proc.poll() is None, "witness exited"
                time.sleep(0.05)
            else:
                raise RuntimeError("witness not ready")
            operator, control = secrets.token_hex(32), secrets.token_hex(32)
            roles = {name: actor(["dispositions"] if name == "registrar" else []) for name in ROLES}
            registry = {"actors": roles, "tokens": {secrets.token_hex(32): r for r in ROLES},
                        "require_task_identity": True, "operator_token": operator, "circuit_operator_token": control}
            substrate = Substrate(directory / "state.db", registry, audit_witness=witness, require_audit_witness=True)
            with real_api(substrate) as post:
                events, result = workflow(substrate, post, operator, control, reason)
            save(directory / "audit.json", events)
            subprocess.run([sys.executable, __file__, "--observe", str(directory), str(port), str(certs)], check=True)
        finally:
            proc.terminate()
            proc.wait(10)
    files = [Path(__file__), ROOT / "tests/real_enforcement_support.py", ROOT / "tests/deployed_authority_service.py",
             ROOT / "tests/acceptance/phase9/test_gateway_boundary.py",
             ROOT / "src/governance_substrate/substrate.py", ROOT / "src/governance_substrate/audit_witness.py"]
    result.update(result="PASS", events=len(events), witnessed_head=verify(directory), provider_calls=0,
                  transport="loopback HTTP and separate mTLS witness process", actor_config=roles,
                  base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  source_sha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
    save(directory / "receipt.json", result)
    print(directory / "receipt.json")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("verification requires Python assertions")
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--approved-referral-reason")
    modes.add_argument("--witness", nargs=2)
    modes.add_argument("--observe", nargs=3)
    modes.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.witness:
        port, certs = args.witness
        serve_witness(address=("127.0.0.1", int(port)), cert_dir=certs)
    elif args.observe:
        directory, port, certs = args.observe
        directory = Path(directory)
        observer = witness_client(port, Path(certs), "observer")
        events = json.loads((directory / "audit.json").read_bytes())
        head = verify_event_chain(events)
        save(directory / "head.json", observer._request("/verify", {"event_id": len(events), "event_hash": head}))
        save(directory / "witness.json", observer._request("/entries", {})["entries"])
        verify(directory)
    elif args.verify:
        print(verify(args.verify))
    else:
        run(args.approved_referral_reason)

