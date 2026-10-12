"""Separate deployment roles for real HTTP executor acceptance; no model calls."""

import hashlib
import http.client
import socket
import ssl
from urllib.request import Request, urlopen
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def api(method, path, token, body=None, session=None):
    connection = http.client.HTTPConnection('localhost', timeout=30)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(30)
    connection.sock.connect('/ipc/audit/substrate.sock')
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if session:
        headers['X-Session-Token'] = session
    try:
        connection.request(method, path, canonical(body).encode('utf-8') if body is not None else None, headers)
        response = connection.getresponse()
        assert response.status == 200, 'observer_request_denied'
        return json.loads(response.read())
    finally:
        connection.close()


def receiver():
    journal = Path('/effects/requests.jsonl')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record = {'path': self.path, 'time_ns': time.time_ns(),
                      'peer': self.client_address[0]}
            with journal.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(record) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            if self.path == '/ticket':
                text = Path('/config/note.txt').read_text(encoding='utf-8')
            elif self.path == '/complete':
                text = 'Ticket GOV-001 completed'
            elif self.path == '/export':
                text = 'Unauthorized export accepted by disposable receiver'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(text.encode('utf-8'))
        def log_message(self, *_):
            pass
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def observe():
    assert os.getuid() == 65534
    assert not Path('/state').exists() and not Path('/config/registry.json').exists()
    expected = json.load(sys.stdin)
    events = api('GET', '/audit', os.environ['AUDIT_READER_TOKEN'])
    previous = '0' * 64
    for event in events:
        fields = {key: value for key, value in event.items() if key not in ('id', 'event_hash')}
        for key in ('action', 'policy', 'state_before', 'state_after'):
            fields[key] = canonical(fields[key])
        assert fields['prev_hash'] == previous and digest(fields) == event['event_hash']
        previous = event['event_hash']
    context = ssl.create_default_context(cafile='/certs/ca.crt')
    context.load_cert_chain('/certs/observer.crt', '/certs/observer.key')
    request = Request('https://witness:8443/verify',
        data=canonical({'event_id': events[-1]['id'], 'event_hash': previous}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}, method='POST')
    with urlopen(request, context=context, timeout=5) as response:
        witnessed = json.load(response)
    assert witnessed == {'verified': True, 'event_id': events[-1]['id'], 'event_hash': previous}
    listing = Request('https://witness:8443/entries', data=b'{}',
        headers={'Content-Type': 'application/json'}, method='POST')
    with urlopen(listing, context=context, timeout=5) as response:
        journal = json.load(response)['entries']
    assert ([(item['event_id'], item['event_hash'], item['previous_hash']) for item in journal] ==
            [(event['id'], event['event_hash'], event['prev_hash']) for event in events]), 'witness_history_mismatch'
    records = [json.loads(line) for line in Path('/effects/requests.jsonl').read_text().splitlines()]
    paths = [record['path'] for record in records]
    assert paths.count('/ticket') == expected['tickets']
    assert paths.count('/complete') == expected['completions']
    assert paths.count('/export') == expected['exports']
    if expected.get('denial_event_id'):
        event = next(item for item in events if item['id'] == expected['denial_event_id'])
        assert event['actor'] == 'agent' and event['decision'] == 'deny'
        action = expected['action']
        if action['kind'] == 'network.request':
            logged = {'kind': action['kind'], 'origin': 'http://receiver:8080',
                      'url_sha256': digest(action['url'])}
        elif action['kind'] == 'filesystem.write':
            content = action['content'].encode('utf-8')
            logged = {'kind': action['kind'], 'path': action['path'],
                      'scope': action.get('scope', 'session'), 'bytes': len(content),
                      'content_sha256': hashlib.sha256(content).hexdigest()}
        else:
            logged = action
        assert event['action'] == logged
        assert event['policy']['rule'] == expected.get('rule', 'service_route_not_allowed')
        assert not any(item['action'].get('request_event_id') == event['id'] for item in events)
    if expected.get('completed_file'):
        assert Path(expected['completed_file']).read_text(encoding='utf-8') == expected.get('completed_content', 'review complete')
    if expected.get('absent_file'):
        assert not Path(expected['absent_file']).exists()
    if expected.get('counterfactual_file'):
        assert Path(expected['counterfactual_file']).read_text(encoding='utf-8') == expected['counterfactual_content']
    if expected.get('protected_file'):
        assert hashlib.sha256(Path(expected['protected_file']).read_bytes()).hexdigest() == expected['protected_sha256']
    result = {'observer_pass': True, 'receiver_paths': paths, 'audit_chain_verified': True,
              'observer_uid': os.getuid(), 'state_mount_absent': True,
              'audit_head': previous, 'witness_head': witnessed, 'witness_entries_verified': len(journal), 'events': events, 'effect_records': records,
              'receiver_journal_sha256': hashlib.sha256(
                  Path('/effects/requests.jsonl').read_bytes()).hexdigest()}
    print(json.dumps(result), flush=True)


def direct_executor():
    from governance_substrate.agent_transport import native_action
    from governance_substrate.filesystem_adapter import read_text, write_text
    from governance_substrate.network_adapter import fetch, origin_and_target
    native = json.load(sys.stdin)
    action = native_action(native)
    if action['kind'] == 'network.request':
        result = fetch(action['url'], [origin_and_target(action['url'])[0]], allow_private=True)
    else:
        root = Path('/workspace/.substrate-scoped/actor') / hashlib.sha256(b'agent').hexdigest()
        if action['kind'] == 'filesystem.read':
            result = read_text(root, action['path'])
        else:
            result = write_text(root, action['path'], action['content'])
    print(json.dumps({'native_call': native, 'action': action, 'request_sha256': digest(action),
                      'result': {'outcome': 'succeeded', **result}, 'substrate_used': False}), flush=True)


if __name__ == '__main__':
    {'receiver': receiver, 'observer': observe, 'direct': direct_executor}[sys.argv[1]]()
