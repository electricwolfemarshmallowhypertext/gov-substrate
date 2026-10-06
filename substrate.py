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
import base64
import copy
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from audit_witness import AuditWitness, MTLSAuditWitness
from filesystem_adapter import MAX_CONTENT, check_target, parts_of, read_text, workspace_snapshot, write_text
from governed_objects import CLASSIFICATIONS, transform
from network_adapter import fetch, origin_and_target
from provider_gateway import (issue_gateway_credential, request_identity,
                              verify_gateway_credential, verify_receipt)
from runtime_supervisor import RuntimeSupervisor, StopResult


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
    control_env = data.get("circuit_operator_token_env")
    control_token = os.environ[control_env] if control_env else None
    if control_token is not None and (not control_token or control_token in tokens or
                                      control_token == operator_token):
        raise ValueError("circuit operator token must be distinct and nonempty")
    providers = copy.deepcopy(data.get("providers", {}))
    gateway_secrets = {}
    if not isinstance(providers, dict):
        raise ValueError("providers must be a mapping")
    for name, grant in providers.items():
        if not isinstance(grant, dict):
            raise ValueError("provider grants must be mappings")
        secret_env = grant.pop("gateway_secret_env", None)
        if secret_env is not None:
            if not isinstance(secret_env, str) or not secret_env:
                raise ValueError("invalid provider gateway secret environment")
            secret = os.environ[secret_env]
            if not secret:
                raise ValueError("provider gateway secret must be nonempty")
            gateway_secrets[name] = secret.encode()
    return {"actors": actors, "tokens": tokens, "operator_token": operator_token,
            "circuit_operator_token": control_token, "providers": providers,
            "gateway_secrets": gateway_secrets, "monitoring": data.get("monitoring"),
            "require_task_identity": data.get("require_task_identity", False)}


class Substrate:
    def __init__(self, db_path: str | Path, registry: dict[str, Any],
                 workspace_root: str | Path | None = None,
                 runtime_supervisor: RuntimeSupervisor | None = None,
                 audit_witness: AuditWitness | None = None,
                 gateway_secrets: dict[str, bytes] | None = None,
                 require_audit_witness: bool = False):
        self.db_path = str(db_path)
        self._execution_lock = threading.RLock()
        self.actors = copy.deepcopy(registry["actors"])
        self.tokens = dict(registry["tokens"])
        self.operator_token = registry["operator_token"]
        self.circuit_operator_token = registry.get("circuit_operator_token")
        if self.circuit_operator_token is not None and (
                not isinstance(self.circuit_operator_token, str) or
                not self.circuit_operator_token or
                self.circuit_operator_token == self.operator_token or
                self.circuit_operator_token in self.tokens):
            raise ValueError("circuit operator token must be distinct and nonempty")
        self.runtime_supervisor = runtime_supervisor
        self.audit_witness = audit_witness
        if type(require_audit_witness) is not bool:
            raise ValueError("require_audit_witness must be a boolean")
        if require_audit_witness and audit_witness is None:
            raise ValueError("high-assurance mode requires an independent audit witness")
        self.gateway_secrets = dict(gateway_secrets or {})
        self.providers = copy.deepcopy(registry.get("providers", {}))
        if not isinstance(self.providers, dict):
            raise ValueError("provider registry must be a mapping")
        provider_keys = {"max_classification", "request", "approval_required_at",
                         "gateway_required"}
        request_keys = {"model", "upstream", "allow_fallbacks", "data_collection",
                        "zdr", "retention"}
        for name, grant in self.providers.items():
            request = grant.get("request") if isinstance(grant, dict) else None
            if (not isinstance(name, str) or not 1 <= len(name) <= 64 or
                    not isinstance(grant, dict) or set(grant) - provider_keys or
                    grant.get("max_classification") not in CLASSIFICATIONS or
                    (request is not None and (
                        not isinstance(request, dict) or set(request) != request_keys or
                        not all(isinstance(request[key], str) and request[key]
                                for key in ("model", "upstream", "data_collection", "retention")) or
                        type(request["allow_fallbacks"]) is not bool or
                        type(request["zdr"]) is not bool)) or
                    (grant.get("approval_required_at") is not None and
                     grant["approval_required_at"] not in CLASSIFICATIONS) or
                    type(grant.get("gateway_required", False)) is not bool):
                raise ValueError("invalid provider transfer grant")
            if grant.get("gateway_required") and (
                    request is None or not isinstance(self.gateway_secrets.get(name), bytes) or
                    not self.gateway_secrets[name]):
                raise ValueError("gateway-required provider needs a verification secret")
        self.monitoring = copy.deepcopy(registry.get("monitoring"))
        if self.monitoring is not None:
            if (not isinstance(self.monitoring, dict) or
                    set(self.monitoring) != {"window_seconds", "actor_denials",
                                             "cross_actor_denials"} or
                    any(type(self.monitoring[key]) is not int or self.monitoring[key] <= 0
                        for key in self.monitoring) or
                    self.circuit_operator_token is None):
                raise ValueError("invalid anomaly monitoring policy")
        self.require_task_identity = registry.get("require_task_identity", False)
        if type(self.require_task_identity) is not bool:
            raise ValueError("require_task_identity must be a boolean")
        self.workspace_root = Path(workspace_root).resolve(strict=True) if workspace_root else None
        if self.workspace_root is not None and not self.workspace_root.is_dir():
            raise ValueError("workspace root must be a directory")
        scoped = ["scopes" in actor.get("filesystem", {}) for actor in self.actors.values()]
        if any(scoped) and not all(scoped):
            raise ValueError("all actors must use the same filesystem authority model")
        self.scoped_filesystem = all(scoped)
        for actor in self.actors.values():
            sensitive_access = actor.get("data", {}).get("sensitive_access")
            if sensitive_access is not None and type(sensitive_access) is not bool:
                raise ValueError("sensitive_access must be a boolean")
            if self.scoped_filesystem:
                scopes = actor["filesystem"]["scopes"]
                if not isinstance(scopes, dict):
                    raise ValueError("filesystem scopes must be a mapping")
                for name in ("session", "actor", "shared"):
                    grant = scopes.get(name, {})
                    if not isinstance(grant, dict) or any(
                            type(grant.get(operation, False)) is not bool
                            for operation in ("read", "write")):
                        raise ValueError("invalid filesystem scope grant")
                channels = scopes.get("shared", {}).get("channels", [])
                if (not isinstance(channels, list) or
                        any(not isinstance(channel, str) or not channel for channel in channels) or
                        len(channels) != len(set(channels))):
                    raise ValueError("invalid shared file channels")
            network = actor["network"]
            if sensitive_access is True and not self.scoped_filesystem:
                raise ValueError("sensitive actors require scoped filesystem authority")
            if sensitive_access is True and "services" not in network:
                raise ValueError("sensitive actors require classified network services")
            if "services" in network:
                if network.get("destinations"):
                    raise ValueError("service policy cannot mix broad destinations")
                services = network["services"]
                if not isinstance(services, list):
                    raise ValueError("network services must be a list")
                seen = set()
                for service in services:
                    if not isinstance(service, dict):
                        raise ValueError("invalid network service")
                    try:
                        origin, _, _, _, target = origin_and_target(service["origin"])
                    except (KeyError, TypeError, ValueError) as exc:
                        raise ValueError("invalid service origin") from exc
                    if target != "/" or origin in seen:
                        raise ValueError("service origins must be unique and path-free")
                    seen.add(origin)
                    mode = service.get("mode")
                    if mode in ("terminal", "publication"):
                        paths = service.get("paths")
                        if (not isinstance(paths, list) or not paths or
                                any(not isinstance(path, str) or not path.startswith("/")
                                    for path in paths) or len(paths) != len(set(paths))):
                            raise ValueError("terminal and publication services require exact paths")
                        if mode == "publication" and sensitive_access is None:
                            raise ValueError("publication requires explicit sensitive_access classification")
                        if service.get("egress", "external") not in ("internal", "external"):
                            raise ValueError("invalid service egress classification")
                        if mode == "publication" and service.get("egress", "external") != "external":
                            raise ValueError("publication service must be external")
                    elif mode != "delegated":
                        raise ValueError("unknown service mode")
        registry_material = {
            "actors": self.actors,
            "actor_token_hashes": {actor: hashlib.sha256(token.encode()).hexdigest()
                                   for token, actor in self.tokens.items()},
            "operator_token_hash": hashlib.sha256(self.operator_token.encode()).hexdigest(),
        }
        if self.circuit_operator_token is not None:
            registry_material["circuit_operator_token_hash"] = hashlib.sha256(
                self.circuit_operator_token.encode()).hexdigest()
        if self.providers:
            registry_material["providers"] = self.providers
        if self.monitoring is not None:
            registry_material["monitoring"] = self.monitoring
        if self.require_task_identity:
            registry_material["require_task_identity"] = True
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
                CREATE TABLE IF NOT EXISTS task_identities (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, parent_id TEXT,
                    token_hash TEXT NOT NULL UNIQUE, capabilities TEXT NOT NULL,
                    expires_at REAL NOT NULL, active INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS task_sessions (
                    session_id TEXT PRIMARY KEY, task_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS generation_sessions (
                    generation_id TEXT PRIMARY KEY, session_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS objects (
                    id TEXT PRIMARY KEY, classification TEXT NOT NULL,
                    media_type TEXT NOT NULL, readers TEXT NOT NULL,
                    parents TEXT NOT NULL, operation TEXT NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS generations (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                    input_ids TEXT NOT NULL, input_hashes TEXT NOT NULL,
                    classification TEXT NOT NULL, status TEXT NOT NULL,
                    output_id TEXT
                );
                CREATE TABLE IF NOT EXISTS generation_providers (
                    generation_id TEXT PRIMARY KEY, provider TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS generation_transfers (
                    generation_id TEXT PRIMARY KEY, request TEXT NOT NULL,
                    request_hash TEXT NOT NULL, approval_id TEXT
                );
                CREATE TABLE IF NOT EXISTS generation_receipts (
                    generation_id TEXT PRIMARY KEY, challenge_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL, status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transfer_approvals (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, session_id TEXT NOT NULL,
                    action_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL,
                    provider TEXT NOT NULL, classification TEXT NOT NULL,
                    token_hash TEXT UNIQUE, expires_at REAL, status TEXT NOT NULL,
                    reason TEXT
                );
                CREATE TABLE IF NOT EXISTS execution_grants (
                    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                    actor TEXT NOT NULL, session_id TEXT NOT NULL,
                    action_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL,
                    policy_hash TEXT NOT NULL, capability TEXT NOT NULL,
                    provider TEXT, expires_at REAL NOT NULL, status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS circuit_stops (
                    scope TEXT NOT NULL, target TEXT NOT NULL,
                    active INTEGER NOT NULL, shutdown_confirmed INTEGER NOT NULL,
                    PRIMARY KEY (scope, target)
                );
                CREATE TABLE IF NOT EXISTS anomaly_signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                    actor TEXT NOT NULL, capability TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, event_id INTEGER NOT NULL
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
                CREATE TRIGGER IF NOT EXISTS objects_no_update BEFORE UPDATE ON objects
                    BEGIN SELECT RAISE(ABORT, 'objects are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS objects_no_delete BEFORE DELETE ON objects
                    BEGIN SELECT RAISE(ABORT, 'objects are immutable'); END;
            """)
            if not db.execute("SELECT 1 FROM events LIMIT 1").fetchone():
                snapshot = self._snapshot(db)
                self._append(db, "system", {"kind": "genesis"},
                             {"rule": "initial_state"}, "allow", snapshot, snapshot)
        if require_audit_witness:
            with self._db() as db:
                if self._snapshot(db) != self._verify(db):
                    raise IntegrityError("state integrity failed at startup")
        if self.runtime_supervisor is not None:
            self._reconcile_runtime()

    def _reconcile_runtime(self):
        results = self.runtime_supervisor.reconcile()
        if any(not item.confirmed for item in results):
            raise RuntimeError("runtime reconciliation could not verify worker shutdown")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                raise IntegrityError("state integrity failed during runtime reconciliation")
            for item in results:
                db.execute("UPDATE generations SET status='revoked' WHERE id=? "
                           "AND status IN ('prepared','claimed')", (item.generation_id,))
                db.execute("UPDATE execution_grants SET status='revoked' "
                           "WHERE action_hash=? AND status='issued'",
                           (digest({"kind": "generation.execute",
                                    "generation_id": item.generation_id}),))
                db.execute("UPDATE generation_receipts SET status='revoked' "
                           "WHERE generation_id=? AND status IN ('issued','dispatched')",
                           (item.generation_id,))
            db.execute("UPDATE circuit_stops SET shutdown_confirmed=1 "
                       "WHERE active=1 AND shutdown_confirmed=0")
            after = self._snapshot(db)
            if results or after != before:
                self._append(db, "system", {"kind": "runtime.reconcile",
                                            "results": [item.audit() for item in results]},
                             {"rule": "orphaned_workers_stopped"}, "allow", before, after)
            db.commit()

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
        task_identities = [dict(row) for row in db.execute(
            "SELECT * FROM task_identities ORDER BY id")]
        task_sessions = [dict(row) for row in db.execute(
            "SELECT * FROM task_sessions ORDER BY session_id")]
        generation_sessions = [dict(row) for row in db.execute(
            "SELECT * FROM generation_sessions ORDER BY generation_id")]
        objects = [{"id": row["id"], "classification": row["classification"],
                    "media_type": row["media_type"], "readers": json.loads(row["readers"]),
                    "parents": json.loads(row["parents"]), "operation": row["operation"],
                    "sha256": hashlib.sha256(row["payload"]).hexdigest(),
                    "bytes": len(row["payload"])}
                   for row in db.execute("SELECT * FROM objects ORDER BY id")]
        generations = [dict(row) for row in db.execute("SELECT * FROM generations ORDER BY id")]
        generation_providers = [dict(row) for row in db.execute(
            "SELECT * FROM generation_providers ORDER BY generation_id")]
        generation_transfers = [dict(row) for row in db.execute(
            "SELECT * FROM generation_transfers ORDER BY generation_id")]
        generation_receipts = [dict(row) for row in db.execute(
            "SELECT * FROM generation_receipts ORDER BY generation_id")]
        approvals = [dict(row) for row in db.execute(
            "SELECT * FROM transfer_approvals ORDER BY id")]
        grants = [dict(row) for row in db.execute(
            "SELECT * FROM execution_grants ORDER BY id")]
        stops = [dict(row) for row in db.execute(
            "SELECT * FROM circuit_stops ORDER BY scope,target")]
        signals = [dict(row) for row in db.execute(
            "SELECT * FROM anomaly_signals ORDER BY id")]
        snapshot = {"state": state, "sessions": sessions}
        if task_identities:
            snapshot["task_identities_sha256"] = digest(task_identities)
        if task_sessions:
            snapshot["task_sessions"] = task_sessions
        if generation_sessions:
            snapshot["generation_sessions"] = generation_sessions
        if objects:
            snapshot["objects"] = objects
        if generations:
            snapshot["generations"] = generations
        if generation_providers:
            snapshot["generation_providers"] = generation_providers
        if generation_transfers:
            snapshot["generation_transfers"] = generation_transfers
        if generation_receipts:
            snapshot["generation_receipts"] = generation_receipts
        if approvals:
            snapshot["transfer_approvals_sha256"] = digest(approvals)
        if grants:
            snapshot["execution_grants_sha256"] = digest(grants)
        if stops:
            snapshot["circuit_stops"] = stops
        if signals:
            snapshot["anomaly_signals_sha256"] = digest(signals)
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
            if row["decision"] in ("allow", "override", "succeeded", "escalate"):
                expected = json.loads(row["state_after"])
        if expected is None:
            raise IntegrityError("audit genesis missing")
        if self.audit_witness is not None:
            try:
                witnessed = self.audit_witness.verify(row["id"], row["event_hash"])
            except Exception as exc:
                raise IntegrityError("independent audit witness unavailable") from exc
            if not witnessed:
                raise IntegrityError("independent audit witness diverged")
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
        event_hash = digest(fields)
        cursor = db.execute(
            "INSERT INTO events (timestamp,actor,action,policy,decision,state_before,"
            "state_after,override_of,elapsed_ms,prev_hash,event_hash) "
            "VALUES (:timestamp,:actor,:action,:policy,:decision,:state_before,"
            ":state_after,:override_of,:elapsed_ms,:prev_hash,:event_hash)",
            {**fields, "event_hash": event_hash},
        )
        if self.audit_witness is not None:
            try:
                self.audit_witness.append(cursor.lastrowid, event_hash, fields["prev_hash"])
            except Exception as exc:
                raise IntegrityError("independent audit witness rejected event") from exc
        return cursor.lastrowid

    def authenticate(self, token: str) -> str | None:
        for candidate, actor in self.tokens.items():
            if hmac.compare_digest(token, candidate):
                return actor
        return None

    def authenticate_principal(self, token: str) -> tuple[str, str | None] | None:
        actor = self.authenticate(token)
        if actor is not None:
            return actor, None
        if not token:
            return None
        with self._db() as db:
            if self._snapshot(db) != self._verify(db):
                raise IntegrityError("state integrity failed")
            row = db.execute(
                "SELECT id,actor FROM task_identities WHERE token_hash=? "
                "AND active=1 AND expires_at>?",
                (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
            return (row["actor"], row["id"]) if row else None

    def issue_task_identity(self, operator_token: str, actor: str,
                            capabilities: list[str], parent_id: str | None = None,
                            ttl_seconds: int = 900) -> dict[str, Any]:
        if not self.is_operator(operator_token):
            raise PermissionError("invalid operator credential")
        known = {"session", "state", "object", "network", "filesystem", "generation"}
        if (actor not in self.actors or type(capabilities) is not list or
                not capabilities or not all(isinstance(item, str) for item in capabilities) or
                len(capabilities) != len(set(capabilities)) or
                not set(capabilities) <= known or type(ttl_seconds) is not int or
                not 1 <= ttl_seconds <= 3600 or
                (parent_id is not None and
                 (not isinstance(parent_id, str) or len(parent_id) != 32))):
            raise ValueError("invalid task authority")
        task_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        expires_at = time.time() + ttl_seconds
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            before = self._snapshot(db)
            if before != self._verify(db):
                raise IntegrityError("state integrity failed")
            if self._stopped(db, actor, "session", None):
                raise ValueError("task authority unavailable during circuit stop")
            parent = None
            if parent_id is not None:
                parent = db.execute("SELECT * FROM task_identities WHERE id=? AND active=1 "
                                    "AND expires_at>?", (parent_id, time.time())).fetchone()
                if (parent is None or parent["actor"] == actor or
                        not set(capabilities) <= set(json.loads(parent["capabilities"])) or
                        expires_at > parent["expires_at"]):
                    raise ValueError("parent task does not grant this authority")
            if db.execute("SELECT 1 FROM task_identities WHERE actor=? AND active=1 "
                          "AND expires_at>?", (actor, time.time())).fetchone():
                raise ValueError("actor already has an active task identity")
            db.execute("INSERT INTO task_identities VALUES (?,?,?,?,?,?,1)",
                       (task_id, actor, parent_id, hashlib.sha256(token.encode()).hexdigest(),
                        canonical(sorted(capabilities)), expires_at))
            after = self._snapshot(db)
            event_id = self._append(db, "human-operator",
                                    {"kind": "task.issue", "task_id": task_id,
                                     "actor": actor, "parent_id": parent_id,
                                     "capabilities": sorted(capabilities),
                                     "expires_at": expires_at},
                                    {"rule": "operator_task_authority"},
                                    "allow", before, after)
            db.commit()
        return {"event_id": event_id, "task_id": task_id, "actor": actor,
                "parent_id": parent_id, "task_token": token,
                "expires_at": expires_at}

    @staticmethod
    def _task_session_live(db: sqlite3.Connection, session_id: str) -> bool:
        row = db.execute("SELECT t.active,t.expires_at FROM task_sessions s "
                         "JOIN task_identities t ON t.id=s.task_id WHERE s.session_id=?",
                         (session_id,)).fetchone()
        return row is None or (bool(row["active"]) and row["expires_at"] > time.time())

    @staticmethod
    def _session_task_id(db: sqlite3.Connection, session_id: str) -> str | None:
        row = db.execute("SELECT task_id FROM task_sessions WHERE session_id=?",
                         (session_id,)).fetchone()
        return row["task_id"] if row else None

    @staticmethod
    def _task_capability(db: sqlite3.Connection, task_id: str, capability: str) -> bool:
        row = db.execute("SELECT capabilities FROM task_identities WHERE id=? AND active=1 "
                         "AND expires_at>?", (task_id, time.time())).fetchone()
        return row is not None and capability in json.loads(row["capabilities"])

    @staticmethod
    def _generation_task_live(db: sqlite3.Connection, generation_id: str) -> bool:
        row = db.execute("SELECT session_id FROM generation_sessions WHERE generation_id=?",
                         (generation_id,)).fetchone()
        return row is None or Substrate._task_session_live(db, row["session_id"])

    def is_operator(self, token: str) -> bool:
        return hmac.compare_digest(token, self.operator_token)

    @staticmethod
    def _transfer_action(action: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in action.items() if key != "approval_token"}

    def approve_transfer(self, token: str, request_id: str,
                         reason: str) -> dict[str, Any]:
        if not self.is_operator(token):
            raise PermissionError("invalid operator credential")
        if (not isinstance(request_id, str) or len(request_id) != 32 or
                not isinstance(reason, str) or not reason.strip()):
            raise ValueError("invalid transfer approval")
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            row = db.execute("SELECT * FROM transfer_approvals WHERE id=?",
                             (request_id,)).fetchone()
            if before != expected:
                raise IntegrityError("state integrity failed")
            if row is None or row["status"] != "pending":
                raise ValueError("transfer approval request is unavailable")
            if not db.execute("SELECT 1 FROM sessions WHERE id=? AND actor=? AND active=1",
                              (row["session_id"], row["actor"])).fetchone():
                raise ValueError("transfer approval session is unavailable")
            if not self._task_session_live(db, row["session_id"]):
                raise ValueError("transfer approval task is unavailable")
            approval_token = secrets.token_urlsafe(32)
            expires_at = time.time() + 120
            db.execute("UPDATE transfer_approvals SET token_hash=?,expires_at=?,status='issued',"
                       "reason=? WHERE id=?",
                       (hashlib.sha256(approval_token.encode()).hexdigest(), expires_at,
                        reason.strip(), request_id))
            after = self._snapshot(db)
            event_id = self._append(
                db, "human-operator",
                {"kind": "provider.transfer.approve", "request_id": request_id,
                 "actor": row["actor"], "provider": row["provider"],
                 "classification": row["classification"], "expires_at": expires_at},
                {"rule": "exact_transfer_approved", "reason": reason.strip()},
                "allow", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "allow",
                "approval_token": approval_token, "expires_at": expires_at}

    def _record_denial_signal(self, actor: str, capability: str,
                              fingerprint: str, source_event_id: int) -> None:
        if self.monitoring is None:
            return
        trigger = None
        detected_at = time.time()
        detected_tick = time.perf_counter()
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                raise IntegrityError("state integrity failed")
            now = detected_at
            db.execute("INSERT INTO anomaly_signals(timestamp,actor,capability,fingerprint,event_id) "
                       "VALUES (?,?,?,?,?)", (now, actor, capability, fingerprint, source_event_id))
            cutoff = now - self.monitoring["window_seconds"]
            actor_count = db.execute(
                "SELECT COUNT(*) FROM anomaly_signals WHERE actor=? AND timestamp>=?",
                (actor, cutoff)).fetchone()[0]
            actors = db.execute(
                "SELECT COUNT(DISTINCT actor) FROM anomaly_signals "
                "WHERE capability=? AND fingerprint=? AND timestamp>=?",
                (capability, fingerprint, cutoff)).fetchone()[0]
            if actors >= self.monitoring["cross_actor_denials"]:
                trigger = ("capability", capability, "automatic_cross_actor_anomaly")
            elif actor_count >= self.monitoring["actor_denials"]:
                trigger = ("actor", actor, "automatic_resource_abuse")
            after = self._snapshot(db)
            self._append(db, "security-monitor",
                         {"kind": "anomaly.observe", "actor": actor,
                          "capability": capability, "fingerprint": fingerprint,
                          "source_event_id": source_event_id},
                         {"rule": "anomaly_signal_recorded"}, "allow", before, after)
            db.commit()
        if trigger is not None:
            try:
                with self._execution_lock:
                    self._set_circuit_locked(*trigger[:2], True, trigger[2],
                                             detected_tick=detected_tick,
                                             detection_event_id=source_event_id)
            except ValueError as exc:
                if "already" not in str(exc):
                    raise

    @staticmethod
    def _capability(action: dict[str, Any]) -> str:
        kind = action.get("kind", "")
        if kind in ("network.request", "object.publish"):
            return "network"
        return kind.split(".", 1)[0] if isinstance(kind, str) else "unknown"

    @staticmethod
    def _stopped(db, actor: str, capability: str, provider: str | None) -> bool:
        targets = [("global", "*"), ("actor", actor), ("capability", capability)]
        if provider is not None:
            targets.append(("provider", provider))
        return any(db.execute(
            "SELECT 1 FROM circuit_stops WHERE scope=? AND target=? AND active=1", target
        ).fetchone() for target in targets)

    @staticmethod
    def _manifest_hash(db, action, context) -> str:
        if action.get("kind") == "generation.prepare" and context is not None:
            return digest({"ids": context[0], "hashes": context[1],
                           "classification": context[2]})
        object_id = action.get("object_id")
        if isinstance(object_id, str):
            row = db.execute("SELECT payload FROM objects WHERE id=?", (object_id,)).fetchone()
            if row is not None:
                return digest({"object_id": object_id,
                               "sha256": hashlib.sha256(row["payload"]).hexdigest()})
        return digest(action)

    def _issue_grant(self, db, actor, session_id, action, manifest_hash,
                     capability, provider, ttl=120):
        token = secrets.token_urlsafe(32)
        grant_id = secrets.token_hex(16)
        expires_at = time.time() + ttl
        before = self._snapshot(db)
        db.execute("INSERT INTO execution_grants VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (grant_id, hashlib.sha256(token.encode()).hexdigest(), actor,
                    session_id, digest(action), manifest_hash, self.registry_hash,
                    capability, provider, expires_at, "issued"))
        after = self._snapshot(db)
        self._append(db, actor, {"kind": "execution.grant.issue", "grant_id": grant_id,
                                 "action_hash": digest(action),
                                 "manifest_hash": manifest_hash, "provider": provider,
                                 "capability": capability, "expires_at": expires_at},
                     {"rule": "execution_grant_issued"}, "allow", before, after)
        return token

    def _use_grant(self, db, token, actor, session_id, action, manifest_hash,
                   capability, provider):
        before = self._snapshot(db)
        token_hash = hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) else ""
        row = db.execute("SELECT * FROM execution_grants WHERE token_hash=?",
                         (token_hash,)).fetchone()
        if row is None:
            rule = "execution_grant_invalid"
        elif row["status"] != "issued":
            rule = "execution_grant_reused"
        elif row["expires_at"] <= time.time():
            rule = "execution_grant_expired"
        elif (row["actor"] != actor or row["session_id"] != session_id or
              row["action_hash"] != digest(action) or
              row["manifest_hash"] != manifest_hash or
              row["policy_hash"] != self.registry_hash or
              row["capability"] != capability or row["provider"] != provider):
            rule = "execution_grant_binding_mismatch"
        elif not db.execute("SELECT 1 FROM sessions WHERE id=? AND actor=? AND active=1",
                            (session_id, actor)).fetchone():
            rule = "execution_session_revoked"
        elif not self._task_session_live(db, session_id):
            rule = "execution_session_revoked"
        elif self._stopped(db, actor, capability, provider):
            rule = "execution_unavailable"
        else:
            rule = None
        if rule is None:
            db.execute("UPDATE execution_grants SET status='used' WHERE id=?", (row["id"],))
        after = self._snapshot(db)
        self._append(db, actor, {"kind": "execution.grant.use",
                                 "grant_id": row["id"] if row else None,
                                 "action_hash": digest(action),
                                 "manifest_hash": manifest_hash,
                                 "capability": capability, "provider": provider},
                     {"rule": rule or "execution_grant_consumed"},
                     "deny" if rule else "allow", before, after)
        return rule

    def set_circuit(self, token: str, scope: str, target: str,
                    active: bool, reason: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._set_circuit(token, scope, target, active, reason)

    def _set_circuit(self, token: str, scope: str, target: str,
                     active: bool, reason: str) -> dict[str, Any]:
        if (self.circuit_operator_token is None or
                not hmac.compare_digest(token, self.circuit_operator_token)):
            raise PermissionError("invalid circuit operator credential")
        if (scope not in ("global", "actor", "capability", "provider") or
                (scope == "global" and target != "*") or
                (scope == "actor" and target not in self.actors) or
                (scope == "capability" and target not in
                 ("session", "state", "object", "network", "filesystem", "generation")) or
                (scope == "provider" and target not in self.providers) or
                type(active) is not bool or not isinstance(reason, str) or not reason.strip()):
            raise ValueError("invalid circuit change")
        with self._execution_lock:
            return self._set_circuit_locked(scope, target, active, reason)

    def _set_circuit_locked(self, scope: str, target: str, active: bool,
                            reason: str, *, detected_tick: float | None = None,
                            detection_event_id: int | None = None) -> dict[str, Any]:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                raise IntegrityError("state integrity failed")
            current = db.execute("SELECT active,shutdown_confirmed FROM circuit_stops "
                                 "WHERE scope=? AND target=?",
                                 (scope, target)).fetchone()
            if not active and current is None:
                raise ValueError("circuit is not active")
            if current is not None and bool(current["active"]) == active:
                raise ValueError("circuit already in requested state")
            if not active and current is not None and not current["shutdown_confirmed"]:
                raise ValueError("runtime shutdown remains unconfirmed")
            db.execute("INSERT INTO circuit_stops VALUES (?,?,?,?) ON CONFLICT(scope,target) "
                       "DO UPDATE SET active=excluded.active, "
                       "shutdown_confirmed=excluded.shutdown_confirmed",
                       (scope, target, int(active), int(not active)))
            affected = []
            if active:
                scoped_actors = {target} if scope == "actor" else set()
                if scope == "actor":
                    descendants = db.execute(
                        "WITH RECURSIVE descendants(id,actor) AS ("
                        "SELECT id,actor FROM task_identities WHERE actor=? "
                        "UNION ALL SELECT child.id,child.actor FROM task_identities child "
                        "JOIN descendants parent ON child.parent_id=parent.id) "
                        "SELECT actor FROM descendants", (target,))
                    scoped_actors.update(row["actor"] for row in descendants)
                grants = list(db.execute("SELECT * FROM execution_grants WHERE status='issued'"))
                for grant in grants:
                    if (scope == "global" or
                            (scope == "actor" and grant["actor"] in scoped_actors) or
                            (scope == "capability" and grant["capability"] == target) or
                            (scope == "provider" and grant["provider"] == target)):
                        db.execute("UPDATE execution_grants SET status='revoked' WHERE id=?",
                                   (grant["id"],))
                        affected.append(grant["actor"])
                approvals = list(db.execute(
                    "SELECT * FROM transfer_approvals WHERE status='issued'"))
                for approval in approvals:
                    if (scope == "global" or
                            (scope == "actor" and approval["actor"] in scoped_actors) or
                            (scope == "capability" and target == "generation") or
                            (scope == "provider" and approval["provider"] == target)):
                        db.execute("UPDATE transfer_approvals SET status='revoked' WHERE id=?",
                                   (approval["id"],))
                        affected.append(approval["actor"])
                runs = list(db.execute("SELECT g.id,g.actor,p.provider FROM generations g "
                                       "LEFT JOIN generation_providers p ON p.generation_id=g.id "
                                       "WHERE g.status IN ('prepared','claimed')"))
                stopped_runs = []
                for run in runs:
                    if (scope == "global" or
                            (scope == "actor" and run["actor"] in scoped_actors) or
                            (scope == "capability" and target == "generation") or
                            (scope == "provider" and run["provider"] == target)):
                        db.execute("UPDATE generations SET status='revoked' WHERE id=?",
                                   (run["id"],))
                        db.execute("UPDATE generation_receipts SET status='revoked' "
                                   "WHERE generation_id=? AND status IN ('issued','dispatched')",
                                   (run["id"],))
                        affected.append(run["actor"])
                        stopped_runs.append(run["id"])
                if scope == "global":
                    db.execute("UPDATE sessions SET active=0")
                    db.execute("UPDATE task_identities SET active=0")
                elif scope == "actor":
                    for scoped_actor in scoped_actors:
                        db.execute("UPDATE sessions SET active=0 WHERE actor=?",
                                   (scoped_actor,))
                        db.execute("UPDATE task_identities SET active=0 WHERE actor=?",
                                   (scoped_actor,))
                elif affected:
                    db.executemany("UPDATE sessions SET active=0 WHERE actor=?",
                                   [(actor,) for actor in set(affected)])
            after = self._snapshot(db)
            trigger_action = {"kind": "circuit.trigger" if active else "circuit.reset",
                              "scope": scope, "target": target}
            if active and detection_event_id is not None:
                trigger_action["detection_event_id"] = detection_event_id
            event_id = self._append(db, "circuit-operator",
                                    trigger_action,
                                    {"rule": "authorized_circuit_control", "reason": reason},
                                    "allow", before, after)
            db.commit()
            tripped_tick = time.perf_counter()
        if active:
            if self.runtime_supervisor is not None and stopped_runs:
                try:
                    shutdowns = self.runtime_supervisor.stop(tuple(stopped_runs))
                except Exception:
                    shutdowns = ()
            else:
                shutdowns = ()
            by_id = {item.generation_id: item for item in shutdowns}
            results = [by_id.get(run_id, StopResult(run_id, "unwired", None,
                                                    False, "stop_unconfirmed"))
                       for run_id in stopped_runs]
            verified = all(item.confirmed for item in results)
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                before = self._snapshot(db)
                if verified:
                    db.execute("UPDATE circuit_stops SET shutdown_confirmed=1 "
                               "WHERE scope=? AND target=?", (scope, target))
                after = self._snapshot(db)
                shutdown_action = {"kind": "circuit.shutdown", "trigger_event_id": event_id,
                                   "results": [item.audit() for item in results]}
                if detected_tick is not None:
                    shutdown_action["detection_to_trip_ms"] = round(
                        max(0.0, tripped_tick - detected_tick) * 1000, 3)
                    shutdown_action["detection_to_shutdown_ms"] = (
                        round(max(0.0, time.perf_counter() - detected_tick) * 1000, 3)
                        if verified else None)
                shutdown_action["trip_to_shutdown_ms"] = (
                    round(max(0.0, time.perf_counter() - tripped_tick) * 1000, 3)
                    if verified else None)
                self._append(db, "circuit-operator", shutdown_action,
                             {"rule": "circuit_shutdown_verified" if verified else
                              "circuit_shutdown_unconfirmed"},
                             "succeeded" if verified else "failed", before, after)
                db.commit()
        return {"event_id": event_id, "decision": "allow",
                "shutdown_confirmed": verified if active else None}

    def create_session(self, actor: str, task_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._create_session(actor, task_id)

    def _create_session(self, actor: str, task_id: str | None = None) -> dict[str, Any]:
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
            if self.require_task_identity and task_id is None:
                event_id = self._append(db, actor, {"kind": "session.create"},
                                        {"rule": "task_identity_required"},
                                        "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny",
                        "reason": "task_identity_required"}
            if self._stopped(db, actor, "session", None):
                event_id = self._append(db, actor, {"kind": "session.create"},
                                        {"rule": "circuit_blocked"}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny",
                        "reason": "capability_unavailable"}
            if task_id is not None:
                task = db.execute("SELECT * FROM task_identities WHERE id=? AND actor=? "
                                  "AND active=1 AND expires_at>?",
                                  (task_id, actor, time.time())).fetchone()
                if task is None or "session" not in json.loads(task["capabilities"]):
                    event_id = self._append(db, actor,
                                            {"kind": "session.create", "task_id": task_id},
                                            {"rule": "task_authority_unavailable"},
                                            "deny", before, before)
                    db.commit()
                    return {"event_id": event_id, "decision": "deny",
                            "reason": "task_authority_unavailable"}
                db.execute("UPDATE sessions SET active=0 WHERE id IN "
                           "(SELECT session_id FROM task_sessions WHERE task_id=?)", (task_id,))
            else:
                db.execute("UPDATE sessions SET active=0 WHERE actor=? AND id NOT IN "
                           "(SELECT session_id FROM task_sessions)", (actor,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,1)",
                       (session_id, actor, hashlib.sha256(token.encode()).hexdigest()))
            if task_id is not None:
                db.execute("INSERT INTO task_sessions VALUES (?,?)", (session_id, task_id))
            if self.scoped_filesystem and self.workspace_root is not None:
                self._scoped_root("session", actor, session_id, None).mkdir(parents=True)
                self._scoped_root("actor", actor, session_id, None).mkdir(parents=True, exist_ok=True)
                for channel in self.actors[actor]["filesystem"]["scopes"].get("shared", {}).get("channels", []):
                    self._scoped_root("shared", actor, session_id, channel).mkdir(parents=True, exist_ok=True)
            after = self._snapshot(db)
            event_id = self._append(db, actor, {"kind": "session.create", "session_id": session_id,
                                                "task_id": task_id},
                                    {"rule": "authenticated_actor"}, "allow", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "allow", "session_id": session_id,
                "task_id": task_id,
                "session_token": token}

    @staticmethod
    def _session_valid(db, actor, session_token):
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        row = db.execute("SELECT id FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                         (actor, token_hash)).fetchone()
        return row is not None and Substrate._task_session_live(db, row["id"])

    def _scoped_root(self, scope: str, actor: str, session_id: str,
                     channel: str | None) -> Path:
        assert self.workspace_root is not None
        namespace = {"session": session_id, "actor": actor,
                     "shared": channel}[scope]
        assert namespace is not None
        label = hashlib.sha256(namespace.encode()).hexdigest()
        return self.workspace_root / ".substrate-scoped" / scope / label

    @staticmethod
    def _insert_object(db, classification, media_type, readers, parents, operation, payload):
        object_id = secrets.token_hex(16)
        db.execute("INSERT INTO objects VALUES (?,?,?,?,?,?,?)",
                   (object_id, classification, media_type, canonical(readers),
                    canonical(parents), operation, payload))
        return object_id

    def import_object(self, classification: str, media_type: str, content_base64: str,
                      readers: list[str], source: str) -> dict[str, Any]:
        if classification not in CLASSIFICATIONS or media_type not in ("text/plain", "image/png"):
            raise ValueError("invalid object classification or media type")
        if (not isinstance(readers, list) or not readers or
                any(reader not in self.actors for reader in readers) or
                len(readers) != len(set(readers))):
            raise ValueError("readers must be unique registered actors")
        if not isinstance(source, str) or not source or len(source) > 128:
            raise ValueError("source identifier required")
        try:
            payload = base64.b64decode(content_base64, validate=True)
        except (TypeError, ValueError, base64.binascii.Error) as exc:
            raise ValueError("invalid base64 content") from exc
        if not payload or len(payload) > MAX_CONTENT:
            raise ValueError("object content must be 1 to 65536 bytes")
        if media_type == "text/plain":
            try:
                payload.decode("utf-8")
            except UnicodeError as exc:
                raise ValueError("text object must be UTF-8") from exc
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            if before != expected:
                event_id = self._append(db, "human-operator", {"kind": "object.import"},
                                        {"rule": "state_integrity"}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny", "reason": "state_integrity"}
            if self._stopped(db, "human-operator", "object", None):
                event_id = self._append(db, "human-operator", {"kind": "object.import"},
                                        {"rule": "circuit_blocked"}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny",
                        "reason": "capability_unavailable"}
            object_id = self._insert_object(db, classification, media_type, sorted(readers),
                                            [], "import", payload)
            after = self._snapshot(db)
            event_id = self._append(db, "human-operator",
                                    {"kind": "object.import", "object_id": object_id,
                                     "classification": classification, "media_type": media_type,
                                     "readers": sorted(readers), "source": source,
                                     "content_sha256": hashlib.sha256(payload).hexdigest()},
                                    {"rule": "trusted_import"}, "allow", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "allow", "object_id": object_id}

    def declassify_object(self, object_id: str, classification: str,
                          reason: str) -> dict[str, Any]:
        if classification not in CLASSIFICATIONS or not isinstance(reason, str):
            raise ValueError("invalid classification or reason")
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            parent = db.execute("SELECT * FROM objects WHERE id=?", (object_id,)).fetchone()
            if before != expected:
                rule = "state_integrity"
            elif self._stopped(db, "human-operator", "object", None):
                rule = "circuit_blocked"
            elif parent is None:
                rule = "object_not_found"
            elif not reason.strip():
                rule = "declassification_reason_required"
            elif CLASSIFICATIONS.index(classification) >= CLASSIFICATIONS.index(parent["classification"]):
                rule = "classification_not_lowered"
            else:
                rule = None
            if rule:
                event_id = self._append(db, "human-operator",
                                        {"kind": "object.declassify", "object_id": object_id,
                                         "target": classification}, {"rule": rule},
                                        "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny",
                        "reason": "capability_unavailable" if rule == "circuit_blocked" else rule}
            child_id = self._insert_object(db, classification, parent["media_type"],
                                           json.loads(parent["readers"]), [object_id],
                                           "declassify", parent["payload"])
            after = self._snapshot(db)
            event_id = self._append(db, "human-operator",
                                    {"kind": "object.declassify", "parent_id": object_id,
                                     "object_id": child_id, "from": parent["classification"],
                                     "to": classification},
                                    {"rule": "human_declassification", "reason": reason},
                                    "override", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "override", "object_id": child_id,
                "parent_id": object_id, "classification": classification}

    @staticmethod
    def _generation_sources(db: sqlite3.Connection, run: sqlite3.Row):
        input_ids = json.loads(run["input_ids"])
        hashes = json.loads(run["input_hashes"])
        if not input_ids or len(input_ids) != len(hashes):
            return None
        sources = [db.execute("SELECT * FROM objects WHERE id=?", (item,)).fetchone()
                   for item in input_ids]
        if any(source is None or hashlib.sha256(source["payload"]).hexdigest() != expected
               for source, expected in zip(sources, hashes)):
            return None
        if max((source["classification"] for source in sources),
               key=CLASSIFICATIONS.index) != run["classification"]:
            return None
        return sources

    @staticmethod
    def _generation_provider(db, generation_id):
        row = db.execute("SELECT provider FROM generation_providers WHERE generation_id=?",
                         (generation_id,)).fetchone()
        return row["provider"] if row else None

    def claim_generation(self, generation_id: str, execution_token: str,
                         provider: str | None = None) -> dict[str, Any]:
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            run = db.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
            provider_row = db.execute("SELECT provider FROM generation_providers WHERE generation_id=?",
                                      (generation_id,)).fetchone()
            sealed_provider = provider_row["provider"] if provider_row else None
            transfer = db.execute("SELECT * FROM generation_transfers WHERE generation_id=?",
                                  (generation_id,)).fetchone()
            sources = self._generation_sources(db, run) if run and before == expected else None
            if before != expected:
                rule = "state_integrity"
            elif run is None:
                rule = "generation_not_found"
            elif run["status"] != "prepared":
                rule = "generation_already_claimed"
            elif not self._generation_task_live(db, generation_id):
                rule = "task_authority_unavailable"
            elif provider != sealed_provider:
                rule = "generation_provider_mismatch"
            elif sources is None:
                rule = "generation_manifest_invalid"
            elif sealed_provider is not None and (
                    transfer is None or transfer["request_hash"] != request_identity(
                        generation_id, sealed_provider, json.loads(transfer["request"]),
                        json.loads(run["input_ids"]), json.loads(run["input_hashes"]))):
                rule = "provider_request_integrity"
            elif self._stopped(db, run["actor"], "generation", sealed_provider):
                rule = "execution_unavailable"
            else:
                rule = None
            action = {"kind": "generation.claim", "generation_id": generation_id,
                      "provider": provider,
                      "request_hash": transfer["request_hash"] if transfer else None}
            if rule:
                event_id = self._append(db, "trusted-generation-adapter", action,
                                        {"rule": rule}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny", "reason": rule}
            grant_action = {"kind": "generation.execute", "generation_id": generation_id}
            manifest_hash = digest({"ids": json.loads(run["input_ids"]),
                                    "hashes": json.loads(run["input_hashes"]),
                                    "classification": run["classification"],
                                    "request_hash": transfer["request_hash"] if transfer else None})
            grant = db.execute("SELECT session_id FROM execution_grants WHERE token_hash=?",
                               (hashlib.sha256(execution_token.encode()).hexdigest(),)
                               ).fetchone() if isinstance(execution_token, str) else None
            grant_rule = self._use_grant(db, execution_token, run["actor"],
                                         grant["session_id"] if grant else "",
                                         grant_action, manifest_hash, "generation", sealed_provider)
            if grant_rule:
                snapshot = self._snapshot(db)
                event_id = self._append(db, "trusted-generation-adapter", action,
                                        {"rule": grant_rule}, "deny", snapshot, snapshot)
                db.commit()
                return {"event_id": event_id, "decision": "deny", "reason": grant_rule}
            before = self._snapshot(db)
            db.execute("UPDATE generations SET status='claimed' WHERE id=?", (generation_id,))
            challenge = None
            if sealed_provider is not None and self.providers[sealed_provider].get(
                    "gateway_required", False):
                expires_at = time.time() + 120
                challenge = issue_gateway_credential(
                    self.gateway_secrets[sealed_provider], run["actor"], generation_id,
                    sealed_provider, transfer["request_hash"], expires_at)
                db.execute("INSERT INTO generation_receipts VALUES (?,?,?,?)",
                           (generation_id, hashlib.sha256(challenge.encode()).hexdigest(),
                            expires_at, "issued"))
            after = self._snapshot(db)
            event_id = self._append(db, "trusted-generation-adapter", action,
                                    {"rule": "sealed_context_claimed", "subject_actor": run["actor"]},
                                    "allow", before, after)
            db.commit()
            inputs = [{"id": source["id"], "sha256": hashlib.sha256(source["payload"]).hexdigest(),
                       "media_type": source["media_type"],
                       "content_base64": base64.b64encode(source["payload"]).decode("ascii")}
                      for source in sources]
        return {"event_id": event_id, "decision": "allow", "generation_id": generation_id,
                "provider": sealed_provider, "inputs": inputs,
                "provider_request": json.loads(transfer["request"]) if transfer else None,
                "request_hash": transfer["request_hash"] if transfer else None,
                **({"gateway_credential": challenge} if challenge is not None else {})}

    def authorize_provider_call(self, generation_id: str, provider: str,
                                gateway_credential: str) -> dict[str, Any]:
        """Consume a gateway credential at the provider-call boundary."""
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            run = db.execute("SELECT * FROM generations WHERE id=?",
                             (generation_id,)).fetchone()
            sealed_provider = self._generation_provider(db, generation_id) if run else None
            transfer = db.execute(
                "SELECT * FROM generation_transfers WHERE generation_id=?",
                (generation_id,)).fetchone() if run else None
            receipt = db.execute(
                "SELECT * FROM generation_receipts WHERE generation_id=?",
                (generation_id,)).fetchone() if run else None
            credential = verify_gateway_credential(
                self.gateway_secrets.get(provider, b""), gateway_credential)
            if before != expected:
                rule = "state_integrity"
            elif run is None or run["status"] != "claimed":
                rule = "provider_call_unavailable"
            elif not self._generation_task_live(db, generation_id):
                rule = "provider_call_revoked"
            elif provider != sealed_provider:
                rule = "provider_call_binding_mismatch"
            elif receipt is None or receipt["status"] != "issued":
                rule = "provider_call_reused" if receipt and receipt["status"] == "dispatched" else "provider_call_revoked"
            elif receipt["expires_at"] <= time.time():
                rule = "provider_call_expired"
            elif (credential is None or credential["actor"] != run["actor"] or
                  credential["generation_id"] != generation_id or
                  credential["provider"] != provider or transfer is None or
                  credential["request_hash"] != transfer["request_hash"] or
                  hashlib.sha256(gateway_credential.encode()).hexdigest() !=
                  receipt["challenge_hash"]):
                rule = "provider_call_binding_mismatch"
            elif self._stopped(db, run["actor"], "generation", provider):
                rule = "provider_call_revoked"
            else:
                rule = None
            if rule is None:
                db.execute("UPDATE generation_receipts SET status='dispatched' "
                           "WHERE generation_id=?", (generation_id,))
            after = self._snapshot(db)
            event_id = self._append(
                db, "trusted-provider-gateway",
                {"kind": "provider.call.authorize", "generation_id": generation_id,
                 "provider": provider,
                 "request_hash": transfer["request_hash"] if transfer else None},
                {"rule": rule or "provider_call_authorized"},
                "deny" if rule else "allow", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "deny" if rule else "allow",
                "reason": rule or "provider_call_authorized"}

    def complete_generation(self, generation_id: str, text: str,
                            receipt: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            payload = text.encode("utf-8") if isinstance(text, str) else b""
        except UnicodeError:
            payload = b""
        with self._execution_lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            run = db.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
            sources = self._generation_sources(db, run) if run and before == expected else None
            provider = self._generation_provider(db, generation_id) if run else None
            transfer = db.execute("SELECT * FROM generation_transfers WHERE generation_id=?",
                                  (generation_id,)).fetchone() if run else None
            receipt_row = db.execute("SELECT * FROM generation_receipts WHERE generation_id=?",
                                     (generation_id,)).fetchone() if run else None
            if before != expected:
                rule = "state_integrity"
            elif run is None:
                rule = "generation_not_found"
            elif run["status"] != "claimed":
                rule = "generation_already_consumed" if run["status"] == "completed" else "generation_not_claimed"
            elif not self._generation_task_live(db, generation_id):
                rule = "task_authority_unavailable"
            elif sources is None:
                rule = "generation_manifest_invalid"
            elif self._stopped(db, run["actor"], "generation", self._generation_provider(db, generation_id)):
                rule = "execution_unavailable"
            elif not payload or len(payload) > MAX_CONTENT:
                rule = "invalid_generation_output"
            elif provider is not None and self.providers[provider].get("gateway_required", False):
                if (receipt_row is None or receipt_row["status"] != "dispatched" or
                        receipt_row["expires_at"] <= time.time() or
                        not verify_receipt(self.gateway_secrets[provider], receipt or {}) or
                        receipt["generation_id"] != generation_id or
                        receipt["provider"] != provider or
                        transfer is None or receipt["request_hash"] != transfer["request_hash"] or
                        receipt["response_hash"] != hashlib.sha256(payload).hexdigest() or
                        hashlib.sha256(receipt["challenge"].encode()).hexdigest() !=
                        receipt_row["challenge_hash"]):
                    rule = "provider_receipt_invalid"
                else:
                    rule = None
            elif receipt is not None:
                rule = "provider_receipt_unexpected"
            else:
                rule = None
            action = {"kind": "generation.complete", "generation_id": generation_id,
                      "provider": provider,
                      "request_hash": transfer["request_hash"] if transfer else None}
            if rule:
                event_id = self._append(db, "trusted-generation-adapter", action,
                                        {"rule": rule}, "deny", before, before)
                db.commit()
                return {"event_id": event_id, "decision": "deny", "reason": rule}
            input_ids = json.loads(run["input_ids"])
            if receipt_row is not None:
                db.execute("UPDATE generation_receipts SET status='used' WHERE generation_id=?",
                           (generation_id,))
            object_id = self._insert_object(db, run["classification"], "text/plain",
                                            [run["actor"]], input_ids, "generate", payload)
            db.execute("UPDATE generations SET status='completed', output_id=? WHERE id=?",
                       (object_id, generation_id))
            after = self._snapshot(db)
            action.update(object_id=object_id, parents=input_ids,
                          classification=run["classification"],
                          content_sha256=hashlib.sha256(payload).hexdigest())
            event_id = self._append(db, "trusted-generation-adapter", action,
                                    {"rule": "sealed_generation_completed", "subject_actor": run["actor"]},
                                    "succeeded", before, after)
            db.commit()
        return {"event_id": event_id, "decision": "succeeded", "object_id": object_id,
                "classification": run["classification"], "parents": input_ids}

    def _decide(self, actor: str, action: dict[str, Any], session_id: str,
                db: sqlite3.Connection):
        kind = action.get("kind")
        caps = self.actors[actor]
        scope = action.get("scope")
        key = action.get("key")
        if kind == "generation.prepare":
            allowed_fields = {"kind", "input_ids", "provider", "provider_request",
                              "approval_token"}
            if set(action) - allowed_fields or not {"kind", "input_ids"}.issubset(action):
                return "deny", "generation_fields_forbidden", None
            provider = action.get("provider")
            if "provider" in action and (
                    not isinstance(provider, str) or not 1 <= len(provider) <= 64):
                return "deny", "invalid_generation_provider", None
            input_ids = action["input_ids"]
            if (type(input_ids) is not list or not 1 <= len(input_ids) <= 16 or
                    any(not isinstance(item, str) or len(item) != 32 for item in input_ids) or
                    len(input_ids) != len(set(input_ids))):
                return "deny", "invalid_generation_inputs", None
            sources = [db.execute("SELECT * FROM objects WHERE id=?", (item,)).fetchone()
                       for item in input_ids]
            if any(source is None or actor not in json.loads(source["readers"])
                   for source in sources):
                return "deny", "object_not_accessible", None
            hashes = [hashlib.sha256(source["payload"]).hexdigest() for source in sources]
            classification = max((source["classification"] for source in sources),
                                 key=CLASSIFICATIONS.index)
            context = (input_ids, hashes, classification, provider)
            if provider is None and ("provider_request" in action or "approval_token" in action):
                return "deny", "provider_request_mismatch", context
            if provider is not None:
                grant = self.providers.get(provider)
                if grant is None:
                    return "deny", "provider_unregistered", context
                expected_request = grant.get("request")
                supplied_request = action.get("provider_request")
                if expected_request != supplied_request:
                    return "deny", "provider_request_mismatch", context
                if CLASSIFICATIONS.index(classification) > CLASSIFICATIONS.index(
                        grant["max_classification"]):
                    return "deny", "provider_classification_denied", context
                threshold = grant.get("approval_required_at")
                if (threshold is not None and
                        CLASSIFICATIONS.index(classification) >= CLASSIFICATIONS.index(threshold)):
                    token_hash = hashlib.sha256(
                        action.get("approval_token", "").encode()).hexdigest()
                    approval = db.execute(
                        "SELECT * FROM transfer_approvals WHERE token_hash=?",
                        (token_hash,)).fetchone()
                    manifest_hash = digest({"ids": input_ids, "hashes": hashes,
                                            "classification": classification})
                    normalized = self._transfer_action(action)
                    if (approval is None or approval["status"] != "issued" or
                            approval["expires_at"] <= time.time() or
                            approval["actor"] != actor or approval["session_id"] != session_id or
                            approval["action_hash"] != digest(normalized) or
                            approval["manifest_hash"] != manifest_hash or
                            approval["provider"] != provider or
                            approval["classification"] != classification):
                        return "escalate", "provider_approval_required", context
                    db.execute("UPDATE transfer_approvals SET status='used' WHERE id=?",
                               (approval["id"],))
                    context = (*context, approval["id"])
            return "allow", "generation_context_sealed", context
        if kind in ("object.read", "object.transform", "object.publish"):
            object_id = action.get("object_id")
            if not isinstance(object_id, str) or len(object_id) != 32:
                return "deny", "invalid_object_id", None
            parent = db.execute("SELECT * FROM objects WHERE id=?", (object_id,)).fetchone()
            if parent is None or actor not in json.loads(parent["readers"]):
                return "deny", "object_not_accessible", None
            if kind == "object.read":
                return "allow", "object_read_granted", parent
            if kind == "object.transform":
                operation = action.get("operation")
                try:
                    transformed, media_type = transform(parent["payload"], parent["media_type"], operation)
                except (ValueError, UnicodeError):
                    return "deny", "unsupported_transform", None
                if not transformed or len(transformed) > MAX_CONTENT:
                    return "deny", "transform_size_limit", None
                return "allow", "provenance_preserved", (parent, transformed, media_type)
            network = caps["network"]
            if not network.get("allowed") or network.get("publication") is not True:
                return "deny", "publication_disabled", None
            destination = action.get("destination")
            try:
                origin, _, _, _, target = origin_and_target(destination)
            except (TypeError, ValueError):
                return "deny", "invalid_destination", None
            if target != "/":
                return "deny", "invalid_destination", None
            service = next((item for item in network.get("services", [])
                            if origin_and_target(item["origin"])[0] == origin), None)
            if service is None or service.get("mode") != "publication":
                return "deny", "publication_destination_not_allowed", None
            if (service.get("egress", "external") == "external" and
                    parent["classification"] != "public"):
                return "deny", "object_classification_blocks_egress", None
            if parent["media_type"] != "text/plain":
                return "deny", "publication_requires_text", None
            content = parent["payload"].decode("utf-8")
            url = origin + service["paths"][0] + "?data=" + quote(content, safe="")
            if len(url) > 2048:
                return "deny", "publication_size_limit", None
            return "allow", "classified_object_granted", (parent, url, origin)
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
                if kind == "state.write" and caps.get("data", {}).get("sensitive_access") is True:
                    return "deny", "sensitive_shared_write_disabled", None
                namespace = f"shared:{channel}"
            else:
                return "deny", "invalid_scope", None
            return "allow", "capability_granted", namespace
        if kind == "network.request":
            if set(action) != {"kind", "url"}:
                return "deny", "invalid_network_request", None
            network = caps["network"]
            if not network["allowed"]:
                return "deny", "network_disabled", None
            try:
                origin, _, _, _, target = origin_and_target(action.get("url"))
                destinations = {origin_and_target(item)[0]
                                for item in network.get("destinations", [])}
            except (TypeError, ValueError):
                return "deny", "invalid_destination", None
            services = network.get("services")
            if services is not None and destinations:
                return "deny", "mixed_service_policy", None
            if origin not in destinations:
                if services is None:
                    return "deny", "destination_not_allowed", None
                if not isinstance(services, list):
                    return "deny", "invalid_service_policy", None
                matched = []
                for service in services:
                    try:
                        service_origin = origin_and_target(service["origin"])[0]
                    except (KeyError, TypeError, ValueError):
                        return "deny", "invalid_service_policy", None
                    if origin == service_origin:
                        matched.append(service)
                if not matched:
                    return "deny", "destination_not_allowed", None
                if len(matched) != 1:
                    return "deny", "invalid_service_policy", None
                service = matched[0]
                if (caps.get("data", {}).get("sensitive_access") is True and
                        service.get("egress", "external") != "internal"):
                    return "deny", "sensitive_external_egress_disabled", None
                if service.get("mode") == "terminal":
                    if target not in service.get("paths", []):
                        return "deny", "service_route_not_allowed", None
                    return "allow", "terminal_service_granted", None
                if service.get("mode") == "publication":
                    path, separator, query = target.partition("?")
                    try:
                        parameters = parse_qsl(query, keep_blank_values=False, strict_parsing=True)
                    except ValueError:
                        return "deny", "invalid_publication_request", None
                    if (path not in service["paths"] or not separator or
                            len(parameters) != 1 or parameters[0][0] != "data" or
                            not parameters[0][1]):
                        return "deny", "invalid_publication_request", None
                    if network.get("publication") is not True:
                        return "deny", "publication_disabled", None
                    return "allow", "publication_granted", None
                if service.get("mode") == "delegated":
                    return "deny", "delegated_service_unmediated", None
                return "deny", "invalid_service_policy", None
            return "allow", "destination_granted", None
        if kind in ("filesystem.read", "filesystem.write"):
            capability = caps["filesystem"]
            if self.scoped_filesystem:
                scope = action.get("scope", "session")
                scopes = capability["scopes"]
                if scope not in ("session", "actor", "shared"):
                    return "deny", "invalid_scope", None
                grant = scopes.get(scope, {})
                if scope == "shared":
                    channel = action.get("channel")
                    if not isinstance(channel, str) or channel not in grant.get("channels", []):
                        return "deny", "shared_channel_disabled", None
                    if (kind == "filesystem.write" and
                            caps.get("data", {}).get("sensitive_access") is True):
                        return "deny", "sensitive_shared_write_disabled", None
                else:
                    channel = None
                operation = "read" if kind == "filesystem.read" else "write"
                if grant.get(operation) is not True:
                    return "deny", f"filesystem_{scope}_{operation}_disabled", None
            else:
                scope, channel = None, None
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
                root = (self._scoped_root(scope, actor, session_id, channel)
                        if self.scoped_filesystem else self.workspace_root)
                check_target(root, path)
            except ValueError:
                return "deny", "path_escape", None
            return "allow", "workspace_scope_granted", root
        if kind == "tool.invoke":
            tool = action.get("tool")
            enabled = isinstance(tool, str) and caps["tools"].get(tool) is True
            return "deny", "tool_adapter_absent" if enabled else "tool_disabled", None
        if kind == "credential.expand":
            return "deny", "credential_scope_fixed", None
        return "deny", "unknown_action", None

    def propose(self, actor: str, session_token: str, action: dict[str, Any],
                execution_token: str | None = None,
                authorize_only: bool = False,
                task_id: str | None = None) -> dict[str, Any]:
        if action.get("kind") in ("network.request", "object.publish"):
            return self._propose(actor, session_token, action, execution_token,
                                 authorize_only, task_id)
        with self._execution_lock:
            return self._propose(actor, session_token, action, execution_token,
                                 authorize_only, task_id)

    def _external_execution_open(self, actor: str, session_token: str,
                                 task_id: str | None = None) -> bool:
        with self._db() as db:
            expected = self._verify(db)
            if self._snapshot(db) != expected:
                return False
            row = db.execute("SELECT id FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                             (actor, hashlib.sha256(session_token.encode()).hexdigest())).fetchone()
            return (row is not None and self._task_session_live(db, row["id"]) and
                    self._session_task_id(db, row["id"]) == task_id and
                    not self._stopped(db, actor, "network", None))

    def _propose(self, actor: str, session_token: str, action: dict[str, Any],
                 execution_token: str | None = None,
                 authorize_only: bool = False,
                 task_id: str | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._verify(db)
            before = self._snapshot(db)
            provider = action.get("provider") if action.get("kind") == "generation.prepare" else None
            capability = self._capability(action)
            approval_request_id = None
            row = db.execute("SELECT id FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                             (actor, hashlib.sha256(session_token.encode()).hexdigest())).fetchone()
            if before != expected:
                decision, rule, namespace = "deny", "state_integrity", None
            elif self.require_task_identity and task_id is None:
                decision, rule, namespace = "deny", "task_identity_required", None
            elif (row is None or not self._task_session_live(db, row["id"]) or
                  self._session_task_id(db, row["id"]) != task_id):
                decision, rule, namespace = "deny", "invalid_session", None
            else:
                session_id = row["id"]
                if self._stopped(db, actor, capability, provider):
                    decision, rule, namespace = "deny", "circuit_blocked", None
                elif task_id is not None and not self._task_capability(db, task_id, capability):
                    decision, rule, namespace = "deny", "task_capability_denied", None
                else:
                    decision, rule, namespace = self._decide(actor, action, session_id, db)
                if decision == "escalate" and rule == "provider_approval_required":
                    approval_request_id = secrets.token_hex(16)
                    normalized = self._transfer_action(action)
                    approval_manifest = digest({"ids": namespace[0], "hashes": namespace[1],
                                                "classification": namespace[2]})
                    db.execute(
                        "INSERT INTO transfer_approvals VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (approval_request_id, actor, session_id, digest(normalized),
                         approval_manifest, namespace[3], namespace[2], None, None,
                         "pending", None))
                if decision == "allow":
                    manifest_hash = self._manifest_hash(db, action, namespace)
                    if authorize_only or execution_token is None:
                        issued_token = self._issue_grant(db, actor, session_id, action,
                                                         manifest_hash, capability, provider)
                    else:
                        issued_token = execution_token
                    if not authorize_only:
                        grant_rule = self._use_grant(db, issued_token, actor, session_id,
                                                     action, manifest_hash, capability, provider)
                        if grant_rule:
                            decision, rule, namespace = "deny", grant_rule, None
                    before = self._snapshot(db)
            value = None
            if decision == "allow" and not authorize_only and action["kind"] == "state.write":
                db.execute("INSERT INTO state VALUES (?,?,?) ON CONFLICT(namespace,key) "
                           "DO UPDATE SET value=excluded.value",
                           (namespace, action["key"], canonical(action.get("value"))))
            elif decision == "allow" and not authorize_only and action["kind"] == "state.read":
                found = db.execute("SELECT value FROM state WHERE namespace=? AND key=?",
                                   (namespace, action["key"])).fetchone()
                value = json.loads(found[0]) if found else None
            elif decision == "allow" and not authorize_only and action["kind"] == "object.transform":
                parent, transformed, media_type = namespace
                value = self._insert_object(db, parent["classification"], media_type,
                                            json.loads(parent["readers"]), [parent["id"]],
                                            action["operation"], transformed)
            elif decision == "allow" and not authorize_only and action["kind"] == "generation.prepare":
                input_ids, hashes, classification, provider = namespace[:4]
                approval_id = namespace[4] if len(namespace) > 4 else None
                value = secrets.token_hex(16)
                db.execute("INSERT INTO generations VALUES (?,?,?,?,?,?,?)",
                           (value, actor, canonical(input_ids), canonical(hashes),
                            classification, "prepared", None))
                db.execute("INSERT INTO generation_sessions VALUES (?,?)", (value, session_id))
                if provider is not None:
                    db.execute("INSERT INTO generation_providers VALUES (?,?)",
                               (value, provider))
                    request = self.providers[provider].get("request") or {}
                    transfer_hash = request_identity(value, provider, request,
                                                     input_ids, hashes)
                    db.execute("INSERT INTO generation_transfers VALUES (?,?,?,?)",
                               (value, canonical(request), transfer_hash, approval_id))
                else:
                    transfer_hash = None
                generation_manifest = digest({"ids": input_ids, "hashes": hashes,
                                              "classification": classification,
                                              "request_hash": transfer_hash})
                generation_token = self._issue_grant(
                    db, actor, session_id,
                    {"kind": "generation.execute", "generation_id": value},
                    generation_manifest, "generation", provider, ttl=300)
            after = self._snapshot(db)
            logged_action = action
            if isinstance(action.get("kind"), str) and action["kind"].startswith("object."):
                logged_action = {"kind": action["kind"]}
                if isinstance(action.get("object_id"), str):
                    logged_action["object_id"] = action["object_id"][:32]
                if action.get("operation") in ("base64", "summary"):
                    logged_action["operation"] = action["operation"]
                if "destination" in action:
                    logged_action["destination_sha256"] = digest(action["destination"])
                if "content" in action:
                    try:
                        logged_action["content_sha256"] = digest(action["content"])
                    except UnicodeError:
                        logged_action["content_sha256"] = "invalid_utf8"
            if action.get("kind") == "generation.prepare":
                logged_action = {"kind": "generation.prepare",
                                  "provider": action.get("provider")}
                if namespace is not None:
                    logged_action.update(input_ids=namespace[0],
                                         input_hashes=namespace[1],
                                          classification=namespace[2])
                    if action.get("provider") is not None:
                        logged_action["provider_request_hash"] = digest(
                            action.get("provider_request") or {})
                    if len(namespace) > 4:
                        logged_action["approval_id"] = namespace[4]
                if approval_request_id is not None:
                    logged_action["approval_request_id"] = approval_request_id
                if decision == "allow":
                    logged_action["generation_id"] = value
            if action.get("kind") == "network.request" and "services" in self.actors[actor]["network"]:
                url = action.get("url")
                try:
                    logged_origin = origin_and_target(url)[0]
                except (TypeError, ValueError):
                    logged_origin = None
                logged_action = {"kind": "network.request", "origin": logged_origin,
                                 "url_sha256": digest(url)}
            if (action.get("kind") == "state.write" and action.get("scope") == "shared" and
                    self.actors[actor].get("data", {}).get("sensitive_access") is True):
                logged_action = {"kind": "state.write", "scope": "shared",
                                 "channel_sha256": digest(action.get("channel")),
                                 "key_sha256": digest(action.get("key")),
                                 "value_sha256": digest(action.get("value"))}
            if action.get("kind") == "filesystem.write" and isinstance(action.get("content"), str):
                content = action["content"].encode("utf-8")
                logged_action = {"kind": "filesystem.write", "path": action.get("path"),
                                 "bytes": len(content), "content_sha256": hashlib.sha256(content).hexdigest()}
                if self.scoped_filesystem:
                    logged_action["scope"] = action.get("scope", "session")
                    if "channel" in action:
                        logged_action["channel"] = action["channel"]
                if self.actors[actor].get("data", {}).get("sensitive_access") is True:
                    logged_action.pop("path", None)
                    logged_action["path_sha256"] = digest(action.get("path"))
                    if "channel" in logged_action:
                        logged_action["channel_sha256"] = digest(logged_action.pop("channel"))
            if rule == "unknown_action":
                logged_action = {"kind": "unknown", "action_sha256": digest(action)}
            if task_id is not None:
                logged_action = {**logged_action, "task_id": task_id}
            event_id = self._append(db, actor, logged_action, {"rule": rule}, decision, before, after,
                                    elapsed_ms=(time.perf_counter() - started) * 1000)
            db.commit()
        result = {"event_id": event_id, "decision": decision, "reason": rule}
        if approval_request_id is not None:
            result["approval_request_id"] = approval_request_id
        if decision == "deny" and rule == "circuit_blocked":
            result["reason"] = "capability_unavailable"
        if decision == "allow" and authorize_only:
            result["execution_token"] = issued_token
            return result
        if decision == "allow" and action["kind"] == "state.read":
            result["value"] = value
        if decision == "allow" and action["kind"] == "object.read":
            result.update(classification=namespace["classification"],
                          media_type=namespace["media_type"],
                          content_base64=base64.b64encode(namespace["payload"]).decode("ascii"))
        if decision == "allow" and action["kind"] == "object.transform":
            result.update(object_id=value, classification=namespace[0]["classification"],
                          media_type=namespace[2], parents=[namespace[0]["id"]])
        if decision == "allow" and action["kind"] == "generation.prepare":
            result.update(generation_id=value, classification=namespace[2],
                           input_ids=namespace[0], provider=namespace[3],
                           execution_token=generation_token)
        if (decision == "deny" and self.monitoring is not None and
                rule not in ("circuit_blocked", "invalid_session", "state_integrity")):
            self._record_denial_signal(actor, capability, digest(logged_action), event_id)
        if decision == "allow" and action["kind"] == "object.publish":
            parent, url, origin = namespace
            try:
                open_boundary = (self._external_execution_open(actor, session_token)
                                 if task_id is None else
                                 self._external_execution_open(actor, session_token, task_id))
                if not open_boundary:
                    raise ValueError("capability_unavailable")
                response = fetch(url, [origin])
                outcome = {key: response[key] for key in
                           ("status", "bytes", "body_sha256", "origin", "resolved_ip")}
                result["outcome"] = "succeeded" if 200 <= response["status"] < 300 else "failed"
            except (OSError, ValueError, http.client.HTTPException) as exc:
                outcome = {"error": type(exc).__name__, "detail": str(exc)[:200]}
                result["outcome"] = "failed"
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                snapshot = self._snapshot(db)
                result["outcome_event_id"] = self._append(
                    db, actor, {"kind": "object.publish.result", "request_event_id": event_id,
                                "object_id": parent["id"], "classification": parent["classification"],
                                "destination": origin, **outcome},
                    {"rule": "adapter_result"}, result["outcome"], snapshot, snapshot,
                    elapsed_ms=(time.perf_counter() - started) * 1000)
                db.commit()
        if decision == "allow" and action["kind"] == "network.request":
            try:
                open_boundary = (self._external_execution_open(actor, session_token)
                                 if task_id is None else
                                 self._external_execution_open(actor, session_token, task_id))
                if not open_boundary:
                    raise ValueError("capability_unavailable")
                network = self.actors[actor]["network"]
                destinations = list(network.get("destinations", []))
                destinations.extend(service["origin"] for service in network.get("services", [])
                                    if service.get("mode") in ("terminal", "publication"))
                response = fetch(action["url"], destinations)
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
                                **({"url_sha256": digest(action["url"])}
                                   if "services" in self.actors[actor]["network"]
                                   else {"url": action["url"]}), **outcome},
                    {"rule": "adapter_result"}, result["outcome"], snapshot, snapshot,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
                db.commit()
        if decision == "allow" and action["kind"] in ("filesystem.read", "filesystem.write"):
            try:
                if action["kind"] == "filesystem.read":
                    response = read_text(namespace, action["path"])
                    result["content"] = response["content"]
                else:
                    response = write_text(namespace, action["path"], action["content"])
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
                    logged_path = (namespace.relative_to(self.workspace_root) / action["path"]).as_posix()
                    entries = [entry for entry in after["workspace"]["entries"]
                               if entry["path"] != logged_path]
                    entries.append({"path": logged_path, "kind": "file",
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
            elif self._stopped(db, "human-operator", "state", None):
                rule = "circuit_blocked"
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
                return {"event_id": rejected_id, "decision": "deny",
                        "reason": "capability_unavailable" if rule == "circuit_blocked" else rule}
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


class ObjectImportRequest(BaseModel):
    classification: str
    media_type: str
    content_base64: str
    readers: list[str]
    source: str


class ObjectDeclassificationRequest(BaseModel):
    object_id: str
    classification: str
    reason: str


class GenerationClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generation_id: str
    execution_token: str
    provider: str | None = None


class GenerationCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generation_id: str
    text: str
    receipt: dict[str, Any] | None = None


class ProviderCallAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generation_id: str
    provider: str
    gateway_credential: str


class ExecutionRequest(BaseModel):
    action: dict[str, Any]
    execution_token: str


class TransferApprovalRequest(BaseModel):
    request_id: str
    reason: str


class TaskIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str
    capabilities: list[str]
    parent_id: str | None = None
    ttl_seconds: int = 900


def create_app(substrate: Substrate) -> FastAPI:
    app = FastAPI(title="Governance Substrate Reference Architecture")

    def principal_from_header(authorization: str | None) -> tuple[str, str | None]:
        token = (authorization or "").removeprefix("Bearer ")
        try:
            principal = substrate.authenticate_principal(token)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc
        if principal is None:
            raise HTTPException(401, "invalid actor token")
        return principal

    def actor_from_header(authorization: str | None) -> str:
        return principal_from_header(authorization)[0]

    @app.post("/tasks/issue")
    def task_issue(body: TaskIdentityRequest,
                   authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        try:
            return substrate.issue_task_identity(token, body.actor, body.capabilities,
                                                 body.parent_id, body.ttl_seconds)
        except PermissionError as exc:
            raise HTTPException(401, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/sessions")
    def session(authorization: str | None = Header(default=None)):
        try:
            actor, task_id = principal_from_header(authorization)
            return substrate.create_session(actor, task_id)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/proposals")
    def proposal(body: Proposal, authorization: str | None = Header(default=None),
                 x_session_token: str | None = Header(default=None)):
        actor, task_id = principal_from_header(authorization)
        try:
            return substrate.propose(actor, x_session_token or "", body.action,
                                     task_id=task_id)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/authorizations")
    def authorization(body: Proposal, authorization: str | None = Header(default=None),
                      x_session_token: str | None = Header(default=None)):
        actor, task_id = principal_from_header(authorization)
        try:
            return substrate.propose(actor, x_session_token or "", body.action,
                                     authorize_only=True, task_id=task_id)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/executions")
    def execution(body: ExecutionRequest, authorization: str | None = Header(default=None),
                  x_session_token: str | None = Header(default=None)):
        actor, task_id = principal_from_header(authorization)
        try:
            return substrate.propose(actor, x_session_token or "", body.action,
                                     execution_token=body.execution_token,
                                     task_id=task_id)
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

    @app.post("/objects/import")
    def object_import(body: ObjectImportRequest, authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid operator token")
        try:
            return substrate.import_object(body.classification, body.media_type,
                                           body.content_base64, body.readers, body.source)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/provider-transfers/approve")
    def provider_transfer_approve(body: TransferApprovalRequest,
                                  authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        try:
            return substrate.approve_transfer(token, body.request_id, body.reason)
        except PermissionError as exc:
            raise HTTPException(401, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/objects/declassify")
    def object_declassify(body: ObjectDeclassificationRequest,
                          authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid operator token")
        try:
            return substrate.declassify_object(body.object_id, body.classification,
                                               body.reason)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/generations/claim")
    def generation_claim(body: GenerationClaimRequest,
                         authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid trusted adapter token")
        try:
            return substrate.claim_generation(body.generation_id, body.execution_token,
                                              body.provider)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/generations/complete")
    def generation_complete(body: GenerationCompleteRequest,
                            authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ")
        if not substrate.is_operator(token):
            raise HTTPException(401, "invalid trusted adapter token")
        try:
            return substrate.complete_generation(body.generation_id, body.text, body.receipt)
        except IntegrityError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/generations/provider-call")
    def provider_call(body: ProviderCallAuthorizationRequest):
        try:
            return substrate.authorize_provider_call(
                body.generation_id, body.provider, body.gateway_credential)
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
    witness = None
    witness_names = ("GOV_SUBSTRATE_WITNESS_URL", "GOV_SUBSTRATE_WITNESS_CA",
                     "GOV_SUBSTRATE_WITNESS_CERT", "GOV_SUBSTRATE_WITNESS_KEY")
    witness_values = [os.environ.get(name) for name in witness_names]
    if any(witness_values):
        if not all(witness_values):
            raise ValueError("all mTLS audit witness settings are required")
        witness = MTLSAuditWitness(*witness_values)
    assurance = os.environ.get("GOV_SUBSTRATE_HIGH_ASSURANCE", "0")
    if assurance not in ("0", "1"):
        raise ValueError("GOV_SUBSTRATE_HIGH_ASSURANCE must be 0 or 1")
    return create_app(Substrate(os.environ.get("GOV_SUBSTRATE_DB", "substrate.db"), registry,
                                os.environ.get("GOV_SUBSTRATE_WORKSPACE"),
                                audit_witness=witness,
                                gateway_secrets=registry["gateway_secrets"],
                                require_audit_witness=assurance == "1"))


app = app_from_env() if os.environ.get("GOV_SUBSTRATE_AUTOSTART") == "1" else FastAPI()
