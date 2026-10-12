"""Standard-library transport and native-request parsing shared by host and worker."""
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


class Response:
    def __init__(self, status, value):
        self.status_code, self.value = status, value

    def json(self):
        return self.value


def native_action(call):
    if type(call) is not dict or type(call.get('function')) is not dict:
        raise ValueError('unsupported_native_tool')
    if call.get('type') != 'function' or not isinstance(call.get('id'), str):
        raise ValueError('unsupported_native_tool')
    name = call['function']['name']
    arguments = json.loads(call['function']['arguments'])
    fields = {'fetch_url': {'url'}, 'read_file': {'path'}, 'write_file': {'path', 'content'}}
    if (name not in fields or type(arguments) is not dict or set(arguments) != fields[name] or
            any(type(value) is not str for value in arguments.values())):
        raise ValueError('invalid_native_tool_arguments')
    if name == 'fetch_url':
        action = {'kind': 'network.request', **arguments}
    else:
        action = {'kind': 'filesystem.read' if name == 'read_file' else 'filesystem.write',
                  'scope': 'actor', **arguments}
    return action


class SubstrateClient:
    def __init__(self, endpoint, token, failure_directory=None):
        self.endpoint, self.token = endpoint, token
        self.session = None
        self.failure_directory = Path(failure_directory) if failure_directory else None

    def _sanitize(self, text, body=None, headers=None):
        if isinstance(text, bytes):
            text = text.decode('utf-8', errors='replace')
        text = str(text)
        sensitive = [self.token, self.session, *(headers or {}).values()]
        sensitive.extend(value for key, value in os.environ.items()
                         if any(word in key.upper() for word in ('TOKEN', 'SECRET', 'API_KEY', 'PASSWORD')))
        def collect(value):
            if isinstance(value, str):
                sensitive.append(value)
            elif isinstance(value, dict):
                for item in value.values():
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)
        collect(body)
        for value in sorted((value for value in sensitive if isinstance(value, str) and value), key=len, reverse=True):
            text = text.replace(value, '[REDACTED]')
        text = re.sub(r'(?i)Bearer\s+[^\s"\x27]+', 'Bearer [REDACTED]', text)
        text = re.sub(r'sk-or-[A-Za-z0-9_-]+', '[REDACTED]', text)
        return '\n'.join(line for line in text.splitlines() if not line.startswith('    '))[-4000:]

    def _failure(self, method, path, reason, body=None, headers=None, **fields):
        entry = {'record_type': 'substrate_failure', 'operation': method + ' ' + path,
                 'reason': reason, **fields}
        entry = {key: self._sanitize(value, body, headers) if isinstance(value, (str, bytes)) else value
                 for key, value in entry.items()}
        if self.failure_directory:
            self.failure_directory.mkdir(parents=True, exist_ok=True)
            target = self.failure_directory / (uuid.uuid4().hex + '.json')
            target.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding='utf-8')
        else:
            # The parent captures this stream in its local worker/service log.
            print(json.dumps(entry, ensure_ascii=False), file=sys.stderr, flush=True)
        return entry

    def _finish(self, method, path, status, value, body, headers):
        if status != 200:
            detail = value.get('detail', 'unspecified failure') if isinstance(value, dict) else 'invalid response body'
            if isinstance(detail, list):
                detail = [{key: item[key] for key in ('loc', 'msg', 'type') if key in item}
                          for item in detail if isinstance(item, dict)]
            if not isinstance(detail, str):
                detail = canonical(detail)
            detail = self._sanitize(detail, body, headers)
            self._failure(method, path, 'http_error', body, headers, status_code=status, detail=detail)
        return Response(status, value)

    def request(self, method, path, body=None, headers=None):
        outgoing = {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}
        if self.session:
            outgoing['X-Session-Token'] = self.session
        outgoing.update(headers or {})
        if self.endpoint.startswith('docker://'):
            container = self.endpoint.removeprefix('docker://')
            if not container or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for char in container):
                raise ValueError('invalid_substrate_container')
            try:
                result = subprocess.run(['docker', 'exec', '-i', container, 'python', '-m',
                                         'governance_substrate.agent', 'rpc'],
                    input=canonical({'method': method, 'path': path, 'body': body, 'headers': outgoing}),
                    capture_output=True, text=True, encoding='utf-8', timeout=45)
            except subprocess.TimeoutExpired as exc:
                failure = self._failure(method, path, 'docker_timeout', body, outgoing,
                                        timeout_seconds=exc.timeout, stderr=exc.stderr or '')
                raise RuntimeError(f"substrate_docker_timeout: operation={failure['operation']}; "
                                   f"timeout={exc.timeout}; stderr={failure['stderr']}") from None
            if result.returncode:
                failure = self._failure(method, path, 'docker_transport_failed', body, outgoing,
                                        exit_code=result.returncode, stderr=result.stderr)
                raise RuntimeError(f"substrate_docker_transport_failed: operation={failure['operation']}; "
                                   f"exit_code={result.returncode}; stderr={failure['stderr']}")
            response = json.loads(result.stdout)
            return self._finish(method, path, response['status'], response['body'], body, outgoing)
        if self.endpoint.startswith('/'):
            connection = UnixConnection(self.endpoint, timeout=30)
        else:
            url = urlsplit(self.endpoint)
            if url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost'):
                raise ValueError('Host API must use a local tunnel or loopback endpoint')
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=30)
        try:
            connection.request(method, path, canonical(body).encode('utf-8') if body is not None else None, outgoing)
            response = connection.getresponse()
            return self._finish(method, path, response.status, json.loads(response.read()), body, outgoing)
        except (OSError, TimeoutError) as exc:
            failure = self._failure(method, path, 'transport_failed', body, outgoing,
                                    exception_type=type(exc).__name__, detail=str(exc))
            raise RuntimeError(f"substrate_transport_failed: operation={failure['operation']}; "
                               f"exception={type(exc).__name__}; detail={failure['detail']}") from None
        finally:
            connection.close()

    def post(self, path, *, json, headers=None):
        return self.request('POST', path, json, headers)

    def api(self, method, path, body=None):
        response = self.request(method, path, body)
        if response.status_code != 200:
            value = response.json()
            detail = value.get('detail', 'unspecified failure') if isinstance(value, dict) else 'invalid response body'
            if isinstance(detail, list):
                detail = [{key: item[key] for key in ('loc', 'msg', 'type') if key in item}
                          for item in detail if isinstance(item, dict)]
            detail = self._sanitize(detail if isinstance(detail, str) else canonical(detail), body)
            raise RuntimeError(f'substrate_http_{response.status_code}: operation={method} {path}; detail={detail}')
        return response.json()

    def start_session(self):
        self.session = self.api('POST', '/sessions', {})['session_token']

    def execute(self, action):
        authorization = self.api('POST', '/authorizations', {'action': action})
        token = authorization.get('execution_token')
        if authorization['decision'] == 'allow':
            if not token:
                raise RuntimeError('execution_grant_absent')
            result = self.api('POST', '/executions', {'action': action, 'execution_token': token})
        else:
            result = authorization
        public_authorization = {key: value for key, value in authorization.items()
                                if key != 'execution_token'}
        if token:
            public_authorization['execution_token_sha256'] = hashlib.sha256(token.encode()).hexdigest()
        return {'action': action, 'request_sha256': digest(action),
                'authorization': public_authorization, 'result': result}

    def native(self, call):
        try:
            return self._native(call)
        except (ValueError, KeyError, TypeError, RuntimeError) as exc:
            reason = self._sanitize(str(exc), call)
            action = {'kind': 'agent.tool.invalid', 'request_sha256': digest(call),
                      'error_type': type(exc).__name__}
            try:
                admission = self.api('POST', '/authorizations', {'action': action})
            except RuntimeError:
                admission = None
            return {'call_id': call.get('id') if isinstance(call, dict) else None,
                    'native_call': call, 'action': action, 'request_sha256': digest(call),
                    'authorization': admission, 'result': {'outcome': 'failed',
                    'reason': 'invalid_or_failed_tool_request', 'detail': reason,
                    'attempt_event_id': admission.get('event_id') if admission else None}}

    def defer(self, call):
        """Submit a deferred call for a decision only; it is never executed."""
        canned = {'outcome': 'not_executed',
                  'reason': 'Read the preceding tool result before requesting this action again.'}
        call_id = call.get('id') if isinstance(call, dict) else None
        try:
            action = native_action(call)
            authorization = self.api('POST', '/authorizations', {'action': action})
        except (ValueError, KeyError, TypeError, RuntimeError) as exc:
            invalid = {'kind': 'agent.tool.invalid', 'request_sha256': digest(call),
                       'error_type': type(exc).__name__}
            try:
                authorization = self.api('POST', '/authorizations', {'action': invalid})
            except RuntimeError:
                authorization = None
            return {'call_id': call_id, 'native_call': call, 'action': invalid,
                    'request_sha256': digest(call), 'authorization': authorization,
                    'deferred': True, 'result': canned}
        public = {key: value for key, value in authorization.items() if key != 'execution_token'}
        if authorization.get('execution_token'):
            public['execution_token_sha256'] = hashlib.sha256(
                authorization['execution_token'].encode()).hexdigest()
            public['grant_unused'] = True
        return {'call_id': call_id, 'native_call': call, 'action': action,
                'request_sha256': digest(action), 'authorization': public,
                'deferred': True, 'result': canned}

    def _native(self, call):
        action = native_action(call)
        return {'call_id': call['id'], 'native_call': call,
                **self.execute(action)}

