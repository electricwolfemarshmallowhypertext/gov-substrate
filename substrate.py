"""A deliberately small, mediated state transition service."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from filesystem_adapter import MAX_CONTENT, check_target, parts_of, read_text, workspace_snapshot, write_text
from network_adapter import fetch, origin_and_target


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class IntegrityError(RuntimeError):
    pass


def load_registry(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("actors"), list):
        raise ValueError("registry must contain an actors list")
    actors = {}
    tokens = {}
    for item in data["actors"]:
        actor = item["id"]
        token = os.environ[item["token_env"]]
        if actor in actors or token in tokens or not token:
            raise ValueError("actor ids and nonempty tokens must be unique")
        actors[actor] = item
        tokens[token] = actor
    operator_token = os.environ[data["operator_token_env"]]
    if not operator_token or operator_token in tokens:
        raise ValueError("operator token must be unique and nonempty")
    return {"actors": actors, "tokens": tokens, "operator_token": operator_token}


class Substrate:
    def __init__(self, db_path: str | Path, registry: dict[str, Any],
                 workspace_root: str | Path | None = None):
        self.db_path = str(db_path)
        self._execution_lock = threading.RLock()
        self.actors = registry["actors"]
        self.tokens = registry["tokens"]
        self.operator_token = registry["operator_token"]
        self.workspace_root = Path(workspace_root).resolve(strict=True) if workspace_root else None
        if self.workspace_root is not None and not self.workspace_root.is_dir():
            raise ValueError("workspace root must be a directory")
        registry_material = {
            "actors": self.actors,
            "actor_token_hashes": {actor: hashlib.sha256(token.encode()).hexdigest()
                                   for token, actor in self.tokens.items()},
            "operator_token_hash": hashlib.sha256(self.operator_token.encode()).hexdigest(),
        }
        if self.workspace_root is not None:
            registry_material["workspace_root"] = str(self.workspace_root)
        self.registry_hash = digest(registry_material)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS state (
                    namespace TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
                    PRIMARY KEY (namespace, key)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                    token_hash TEXT NOT NULL, active INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, policy TEXT NOT NULL,
                    decision TEXT NOT NULL, state_before TEXT NOT NULL,
                    state_after TEXT NOT NULL, override_of INTEGER,
                    elapsed_ms REAL NOT NULL, prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                    BEGIN SELECT RAISE(ABORT, 'audit events are append only'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                    BEGIN SELECT RAISE(ABORT, 'audit events are append only'); END;
            """)
            if not db.execute("SELECT 1 FROM events LIMIT 1").fetchone():
                snapshot = self._snapshot(db)
                self._append(db, "system", {"kind": "genesis"},
                             {"rule": "initial_state"}, "allow", snapshot, snapshot)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def _snapshot(self, db: sqlite3.Connection) -> dict[str, Any]:
        state = [dict(r) for r in db.execute(
            "SELECT namespace,key,value FROM state ORDER BY namespace,key")]
        sessions = {r["id"]: {"actor": r["actor"], "token_hash": r["token_hash"],
                              "active": bool(r["active"])}
                    for r in db.execute("SELECT * FROM sessions ORDER BY id")}
        snapshot = {"state": state, "sessions": sessions}
        if self.workspace_root is not None:
            snapshot["workspace"] = workspace_snapshot(self.workspace_root)
        return snapshot

    @staticmethod
    def _event_fields(row: sqlite3.Row) -> dict[str, Any]:
        return {key: row[key] for key in (
            "timestamp", "actor", "action", "policy", "decision", "state_before",
            "state_after", "override_of", "elapsed_ms", "prev_hash")}

    def _verify(self, db: sqlite3.Connection) -> dict[str, Any]:
        previous = "0" * 64
        expected = None
        for row in db.execute("SELECT * FROM events ORDER BY id"):
            fields = self._event_fields(row)
            if row["prev_hash"] != previous or digest(fields) != row["event_hash"]:
                raise IntegrityError(f"audit chain invalid at event {row['id']}")
            if json.loads(row["policy"]).get("registry_hash") != self.registry_hash:
                raise IntegrityError("capability registry changed without an audited migration")
            previous = row["event_hash"]
            if row["decision"] in ("allow", "override", "succeeded"):
                expected = json.loads(row["state_after"])
        if expected is None:
            raise IntegrityError("audit genesis missing")
        return expected

    def _append(self, db, actor, action, policy, decision, before, after,
                override_of=None, elapsed_ms=0.0):
        previous = db.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        fields = {
            "timestamp": time.time(), "actor": actor, "action": canonical(action),
            "policy": canonical({**policy, "registry_hash": self.registry_hash}), "decision": decision,
            "state_before": canonical(before), "state_after": canonical(after),
            "override_of": override_of, "elapsed_ms": elapsed_ms,
            "prev_hash": previous[0] if previous else "0" * 64,
        }
        cursor = db.execute(
            "INSERT INTO events (timestamp,actor,action,policy,decision,state_before,"
            "state_after,override_of,elapsed_ms,prev_hash,event_hash) "
            "VALUES (:timestamp,:actor,:action,:policy,:decision,:state_before,"
            ":state_after,:override_of,:elapsed_ms,:prev_hash,:event_hash)",
            {**fields, "event_hash": digest(fields)},
        )
        return cursor.lastrowid

    def authenticate(self, token: str) -> str | None:
        for candidate, actor in self.tokens.items():
            if hmac.compare_digest(token, candidate):
                return actor
        return None

    def is_operator(self, token: str) -> bool:
        return hmac.compare_digest(token, self.operator_token)

    def create_session(self, actor: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._create_session(actor)

    def _create_session(self, actor: str) -> dict[str, Any]:
        session_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                event_id = self._append(db, actor, {"kind": "session.create"},
                                        {"rule": "state_integrity"}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny", "reason": "state_integrity"}
            db.execute("UPDATE sessions SET active=0 WHERE actor=?", (actor,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,1)",
                       (session_id, actor, hashlib.sha256(token.encode()).hexdigest()))
            after = self._snapshot(db)
            event_id = self._append(db, actor, {"kind": "session.create", "session_id": session_id},
                                    {"rule": "authenticated_actor"}, "allow", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "allow", "session_id": session_id,
                "session_token": token}

    @staticmethod
    def _session_valid(db, actor, session_token):
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        return db.execute("SELECT 1 FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                          (actor, token_hash)).fetchone() is not None

    def _decide(self, actor: str, action: dict[str, Any], session_id: str):
        kind = action.get("kind")
        caps = self.actors[actor]
        scope = action.get("scope")
        key = action.get("key")
        if kind in ("state.write", "state.read"):
            if not isinstance(key, str) or not key or len(key) > 128:
                return "deny", "invalid_key", None
            if scope == "session":
                if not caps["persistence"]["session"]:
                    return "deny", "session_persistence_disabled", None
                namespace = f"session:{session_id}:{actor}"
            elif scope == "persistent":
                namespace = f"persistent:{actor}"
                if not caps["persistence"]["cross_session"]:
                    return ("escalate" if kind == "state.write" else "deny"), "cross_session_disabled", namespace
            elif scope == "shared":
                channel = action.get("channel")
                if not isinstance(channel, str) or channel not in caps.get("shared_channels", []):
                    return "deny", "shared_channel_disabled", None
                namespace = f"shared:{channel}"
            else:
                return "deny", "invalid_scope", None
            return "allow", "capability_granted", namespace
        if kind == "network.request":
            network = caps["network"]
            if not network["allowed"]:
                return "deny", "network_disabled", None
            try:
                origin = origin_and_target(action.get("url"))[0]
                destinations = {origin_and_target(item)[0]
                                for item in network.get("destinations", [])}
            except (TypeError, ValueError):
                return "deny", "invalid_destination", None
            if origin not in destinations:
                return "deny", "destination_not_allowed", None
            return "allow", "destination_granted", None
        if kind in ("filesystem.read", "filesystem.write"):
            capability = caps["filesystem"]
            if kind == "filesystem.read" and not capability["read"]:
                return "deny", "filesystem_read_disabled", None
            if kind == "filesystem.write" and capability["write"] != "workspace_only":
                return "deny", "filesystem_write_disabled", None
            if self.workspace_root is None:
                return "deny", "filesystem_adapter_absent", None
            path = action.get("path")
            try:
                parts_of(path)
            except ValueError:
                return "deny", "invalid_path", None
            if kind == "filesystem.write":
                protected = capability.get("protected", [])
                if any(path == item or (item.endswith("/") and path.startswith(item))
                       for item in protected):
                    return "deny", "protected_path", None
                content = action.get("content")
                if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_CONTENT:
                    return "deny", "invalid_content", None
            try:
                check_target(self.workspace_root, path)
            except ValueError:
                return "deny", "path_escape", None
            return "allow", "workspace_scope_granted", None
        if kind == "tool.invoke":
            tool = action.get("tool")
            enabled = isinstance(tool, str) and caps["tools"].get(tool) is True
            return "deny", "tool_adapter_absent" if enabled else "tool_disabled", None
        if kind == "credential.expand":
            return "deny", "credential_scope_fixed", None
        return "deny", "unknown_action", None

    def propose(self, actor: str, session_token: str, action: dict[str, Any]) -> dict[str, Any]:
        with self._execution_lock:
            return self._propose(actor, session_token, action)

    def _propose(self, actor: str, session_token: str, action: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            row = db.execute("SELECT id FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                             (actor, hashlib.sha256(session_token.encode()).hexdigest())).fetchone()
            if before != expected:
                decision, rule, namespace = "deny", "state_integrity", None
            elif row is None:
                decision, rule, namespace = "deny", "invalid_session", None
            else:
                session_id = row["id"]
                decision, rule, namespace = self._decide(actor, action, session_id)
            value = None
            if decision == "allow" and action["kind"] == "state.write":
                db.execute("INSERT INTO state VALUES (?,?,?) ON CONFLICT(namespace,key) "
                           "DO UPDATE SET value=excluded.value",
                           (namespace, action["key"], canonical(action.get("value"))))
            elif decision == "allow" and action["kind"] == "state.read":
                found = db.execute("SELECT value FROM state WHERE namespace=? AND key=?",
                                   (namespace, action["key"])).fetchone()
                value = json.loads(found[0]) if found else None
            after = self._snapshot(db)
            logged_action = action
            if action.get("kind") == "filesystem.write" and isinstance(action.get("content"), str):
                content = action["content"].encode("utf-8")
                logged_action = {"kind": "filesystem.write", "path": action.get("path"),
                                 "bytes": len(content), "content_sha256": hashlib.sha256(content).hexdigest()}
            event_id = self._append(db, actor, logged_action, {"rule": rule}, decision, before, after,
                                    elapsed_ms=(time.perf_counter() - started) * 1000)
            db.commit()
        result = {"event_id": event_id, "decision": decision, "reason": rule}
        if decision == "allow" and action["kind"] == "state.read":
            result["value"] = value
        if decision == "allow" and action["kind"] == "network.request":
            try:
                response = fetch(action["url"], self.actors[actor]["network"]["destinations"])
                outcome = {key: response[key] for key in
                           ("status", "bytes", "body_sha256", "origin", "resolved_ip")}
                result["response"] = {"status": response["status"], "body": response["body"]}
                result["outcome"] = "succeeded"
            except (OSError, ValueError, http.client.HTTPException) as exc:
                outcome = {"error": type(exc).__name__, "detail": str(exc)[:200]}
                result["outcome"] = "failed"
                result["error"] = outcome["detail"]
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                snapshot = self._snapshot(db)
                result["outcome_event_id"] = self._append(
                    db, actor, {"kind": "network.result", "request_event_id": event_id,
                                "url": action["url"], **outcome},
                    {"rule": "adapter_result"}, result["outcome"], snapshot, snapshot,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
                db.commit()
        if decision == "allow" and action["kind"] in ("filesystem.read", "filesystem.write"):
            try:
                if action["kind"] == "filesystem.read":
                    response = read_text(self.workspace_root, action["path"])
                    result["content"] = response["content"]
                else:
                    response = write_text(self.workspace_root, action["path"], action["content"])
                outcome = {key: response[key] for key in ("bytes", "sha256")}
                result["outcome"] = "succeeded"
            except (OSError, ValueError, UnicodeError) as exc:
                outcome = {"error": type(exc).__name__, "detail": str(exc)[:200]}
                result["outcome"] = "failed"
                result["error"] = outcome["detail"]
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                current = self._snapshot(db)
                expected_current = after
                if result["outcome"] == "succeeded" and action["kind"] == "filesystem.write":
                    entries = [entry for entry in after["workspace"]["entries"]
                               if entry["path"] != action["path"]]
                    entries.append({"path": action["path"], "kind": "file",
                                    "sha256": outcome["sha256"], "size": outcome["bytes"]})
                    expected_current = {**after, "workspace": {
                        **after["workspace"],
                        "entries": sorted(entries, key=lambda entry: entry["path"]),
                    }}
                if result["outcome"] == "succeeded" and current != expected_current:
                    outcome = {"error": "state_integrity"}
                    result["outcome"] = "failed"
                    result["error"] = "state_integrity"
                    result.pop("content", None)
                result["outcome_event_id"] = self._append(
                    db, actor, {"kind": "filesystem.result", "request_event_id": event_id,
                                "path": action["path"], **outcome},
                    {"rule": "adapter_result"}, result["outcome"], after, current,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
                db.commit()
        return result

    def override(self, event_id: int, reason: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._override(event_id, reason)

    def _override(self, event_id: int, reason: str) -> dict[str, Any]:
        started = time.perf_counter()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                rule = "state_integrity"
                target = None
            else:
                target = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
                if not reason.strip():
                    rule = "override_reason_required"
                elif target is None or target["decision"] != "escalate":
                    rule = "target_not_escalated"
                elif db.execute("SELECT 1 FROM events WHERE override_of=?", (event_id,)).fetchone():
                    rule = "already_overridden"
                else:
                    rule = None
            if rule is not None:
                rejected_id = self._append(
                    db, "human-operator", {"kind": "override.request", "target": event_id},
                    {"rule": rule, "reason": reason}, "deny", before, before,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
                db.commit()
                return {"event_id": rejected_id, "decision": "deny", "reason": rule}
            action = json.loads(target["action"])
            if action.get("kind") != "state.write" or action.get("scope") != "persistent":
                rejected_id = self._append(
                    db, "human-operator", {"kind": "override.request", "target": event_id},
                    {"rule": "unsupported_override_target", "reason": reason},
                    "deny", before, before,
                )
                db.commit()
                return {"event_id": rejected_id, "decision": "deny", "reason": "unsupported_override_target"}
            actor = target["actor"]
            db.execute("INSERT INTO state VALUES (?,?,?) ON CONFLICT(namespace,key) "
                       "DO UPDATE SET value=excluded.value",
                       (f"persistent:{actor}", action["key"], canonical(action.get("value"))))
            after = self._snapshot(db)
            override_id = self._append(
                db, "human-operator", action,
                {"rule": "one_shot_override", "reason": reason, "subject_actor": actor},
                "override", before, after, override_of=event_id,
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
            db.commit()
        return {"event_id": override_id, "decision": "override", "override_of": event_id}

    def audit(self) -> list[dict[str, Any]]:
        with self._execution_lock:
            return self._audit()

    def _audit(self) -> list[dict[str, Any]]:
        with self._db() as db:
            self._verify(db)
            return [{**dict(row), "action": json.loads(row["action"]),
                     "policy": json.loads(row["policy"]),
                     "state_before": json.loads(row["state_before"]),
                     "state_after": json.loads(row["state_after"])}
                    for row in db.execute("SELECT * FROM events ORDER BY id")]

    def health(self) -> dict[str, Any]:
        with self._execution_lock:
            return self._health()

    def _health(self) -> dict[str, Any]:
        with self._db() as db:
            try:
                expected = self._verify(db)
                current = self._snapshot(db)
                legibility = 1.0 if current == expected else 0.0
                chain_valid = True
            except IntegrityError:
                legibility = 0.0
                chain_valid = False
            rows = list(db.execute("SELECT * FROM events WHERE actor!='system' ORDER BY id"))
        overrides = [r for r in rows if r["decision"] == "override"]
        by_id = {r["id"]: r for r in rows}
        delays = [r["timestamp"] - by_id[r["override_of"]]["timestamp"]
                  for r in overrides if r["override_of"] in by_id]
        plasticity = sorted(delays)[len(delays) // 2] if delays else None
        groups: dict[str, dict[str, list[float]]] = {}
        for r in rows:
            if r["decision"] in ("allow", "deny", "escalate"):
                action = json.loads(r["action"])
                groups.setdefault(str(action.get("kind")), {}).setdefault(r["actor"], []).append(r["elapsed_ms"])
        ratios = []
        for actors in groups.values():
            medians = []
            for samples in actors.values():
                if len(samples) >= 2:
                    ordered = sorted(samples)
                    medians.append(ordered[len(ordered) // 2])
            if len(medians) >= 2 and max(medians) > 0:
                ratios.append(min(medians) / max(medians))
        friction = min(ratios) if ratios else None
        attributable = sum(bool(r["actor"] and json.loads(r["policy"]).get("rule")) for r in rows)
        accountability = (attributable / len(rows) if chain_valid else 0.0) if rows else None
        return {"legibility": legibility, "plasticity_seconds": plasticity,
                "friction_coherence": friction, "accountability_topology": accountability,
                "attempts": len(rows)}


class Proposal(BaseModel):
    action: dict[str, Any]


class OverrideRequest(BaseModel):
    event_id: int
    reason: str


def create_app(substrate: Substrate) -> FastAPI:
    app = FastAPI(title="Governance Substrate Reference Architecture")

    def actor_from_header(authorization: str | None) -> str:
        token = (authorization or "").removeprefix("Bearer ")
        actor = substrate.authenticate(token)
        if actor is None:
            raise HTTPException(401, "invalid actor token")
        return actor

    @app.post("/sessions")
    def session(authorization: str | None = Header(default=None)):
        try:
            return substrate.create_session(actor_from_header(authorization))
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/proposals")
    def proposal(body: Proposal, authorization: str | None = Header(default=None),
                 x_session_token: str | None = Header(default=None)):
        actor = actor_from_header(authorization)
        try:
            return substrate.propose(actor, x_session_token or "", body.action)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/overrides")
    def override(body: OverrideRequest, authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid operator token")
        try:
            return substrate.override(body.event_id, body.reason)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/health")
    def health(authorization: str | None = Header(default=None)):
        actor_from_header(authorization)
        return substrate.health()

    @app.get("/audit")
    def audit(authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid operator token")
        try:
            return substrate.audit()
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    return app


def app_from_env() -> FastAPI:
    registry = load_registry(os.environ.get("GOV_SUBSTRATE_REGISTRY", "registry.example.yaml"))
    return create_app(Substrate(os.environ.get("GOV_SUBSTRATE_DB", "substrate.db"), registry,
                                os.environ.get("GOV_SUBSTRATE_WORKSPACE")))


app = app_from_env() if os.environ.get("GOV_SUBSTRATE_AUTOSTART") == "1" else FastAPI()
