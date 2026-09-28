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
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from filesystem_adapter import MAX_CONTENT, check_target, parts_of, read_text, workspace_snapshot, write_text
from governed_objects import CLASSIFICATIONS, transform
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
                CREATE TABLE IF NOT EXISTS objects (
                    id TEXT PRIMARY KEY, classification TEXT NOT NULL,
                    media_type TEXT NOT NULL, readers TEXT NOT NULL,
                    parents TEXT NOT NULL, operation TEXT NOT NULL,
                    payload BLOB NOT NULL
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
        objects = [{"id": row["id"], "classification": row["classification"],
                    "media_type": row["media_type"], "readers": json.loads(row["readers"]),
                    "parents": json.loads(row["parents"]), "operation": row["operation"],
                    "sha256": hashlib.sha256(row["payload"]).hexdigest(),
                    "bytes": len(row["payload"])}
                   for row in db.execute("SELECT * FROM objects ORDER BY id")]
        snapshot = {"state": state, "sessions": sessions}
        if objects:
            snapshot["objects"] = objects
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
            if self.scoped_filesystem and self.workspace_root is not None:
                self._scoped_root("session", actor, session_id, None).mkdir(parents=True)
                self._scoped_root("actor", actor, session_id, None).mkdir(parents=True, exist_ok=True)
                for channel in self.actors[actor]["filesystem"]["scopes"].get("shared", {}).get("channels", []):
                    self._scoped_root("shared", actor, session_id, channel).mkdir(parents=True, exist_ok=True)
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
                return {"event_id": event_id, "decision": "deny", "reason": rule}
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

    def _decide(self, actor: str, action: dict[str, Any], session_id: str,
                db: sqlite3.Connection):
        kind = action.get("kind")
        caps = self.actors[actor]
        scope = action.get("scope")
        key = action.get("key")
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
                decision, rule, namespace = self._decide(actor, action, session_id, db)
            value = None
            if decision == "allow" and action["kind"] == "state.write":
                db.execute("INSERT INTO state VALUES (?,?,?) ON CONFLICT(namespace,key) "
                           "DO UPDATE SET value=excluded.value",
                           (namespace, action["key"], canonical(action.get("value"))))
            elif decision == "allow" and action["kind"] == "state.read":
                found = db.execute("SELECT value FROM state WHERE namespace=? AND key=?",
                                   (namespace, action["key"])).fetchone()
                value = json.loads(found[0]) if found else None
            elif decision == "allow" and action["kind"] == "object.transform":
                parent, transformed, media_type = namespace
                value = self._insert_object(db, parent["classification"], media_type,
                                            json.loads(parent["readers"]), [parent["id"]],
                                            action["operation"], transformed)
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
                    logged_action["content_sha256"] = digest(action["content"])
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
                                 "channel": action.get("channel"), "key": action.get("key"),
                                 "value_sha256": digest(action.get("value"))}
            if action.get("kind") == "filesystem.write" and isinstance(action.get("content"), str):
                content = action["content"].encode("utf-8")
                logged_action = {"kind": "filesystem.write", "path": action.get("path"),
                                 "bytes": len(content), "content_sha256": hashlib.sha256(content).hexdigest()}
                if self.scoped_filesystem:
                    logged_action["scope"] = action.get("scope", "session")
                    if "channel" in action:
                        logged_action["channel"] = action["channel"]
            event_id = self._append(db, actor, logged_action, {"rule": rule}, decision, before, after,
                                    elapsed_ms=(time.perf_counter() - started) * 1000)
            db.commit()
        result = {"event_id": event_id, "decision": decision, "reason": rule}
        if decision == "allow" and action["kind"] == "state.read":
            result["value"] = value
        if decision == "allow" and action["kind"] == "object.read":
            result.update(classification=namespace["classification"],
                          media_type=namespace["media_type"],
                          content_base64=base64.b64encode(namespace["payload"]).decode("ascii"))
        if decision == "allow" and action["kind"] == "object.transform":
            result.update(object_id=value, classification=namespace[0]["classification"],
                          media_type=namespace[2], parents=[namespace[0]["id"]])
        if decision == "allow" and action["kind"] == "object.publish":
            parent, url, origin = namespace
            try:
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
