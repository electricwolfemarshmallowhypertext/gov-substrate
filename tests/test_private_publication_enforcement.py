"""Real HTTP publication effect and private-object denial, without mocks."""
import base64
import json
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import uvicorn
from governance_substrate.substrate import Substrate, create_app, digest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_tool_enforcement import CLIENT


def run_private_publication(action_factory=None):
    directory = ROOT / 'dist/private-publication-proof' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(parse_qs(urlsplit(self.path).query)['data'][0])
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *_):
            pass

    receiver = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
    receiver_thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    receiver_thread.start()
    server = api_thread = listener = None
    try:
        origin = f'http://127.0.0.1:{receiver.server_port}'
        token = secrets.token_hex(32)
        actor = {'network': {'allowed': True, 'publication': True,
            'private_ip_origins': [origin], 'services': [
                {'origin': origin, 'mode': 'publication', 'egress': 'external',
                 'paths': ['/publish']}]},
            'filesystem': {'read': False, 'write': False}, 'tools': {},
            'persistence': {'session': True, 'cross_session': False},
            'shared_channels': [], 'data': {'sensitive_access': False}}
        substrate = Substrate(directory / 'substrate.db', {
            'actors': {'agent': actor}, 'tokens': {token: 'agent'},
            'operator_token': secrets.token_hex(32)})
        payloads = {label: label + '-canary-' + secrets.token_hex(32)
                    for label in ('public', 'private')}
        objects = {label: substrate.import_object(label, 'text/plain',
            base64.b64encode(value.encode()).decode(), ['agent'], 'real-publication-control')
            ['object_id'] for label, value in payloads.items()}
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen()
        url = f'http://127.0.0.1:{listener.getsockname()[1]}'
        server = uvicorn.Server(uvicorn.Config(create_app(substrate), log_level='error'))
        api_thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        api_thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            assert api_thread.is_alive() and time.monotonic() < deadline
            time.sleep(0.01)

        def submit(action):
            p = subprocess.run([sys.executable, '-c', CLIENT], input=json.dumps({
                'url': url, 'token': token, 'action': action}), text=True,
                capture_output=True, check=True, timeout=15)
            return json.loads(p.stdout)

        allowed_action = {'kind': 'object.publish', 'object_id': objects['public'],
                          'destination': origin}
        allowed = submit(allowed_action)
        assert allowed['decision'] == 'allow' and allowed['outcome'] == 'succeeded', allowed
        assert received == [payloads['public']]
        denied_action = (action_factory('publish_object', {'object_id': objects['private'], 'destination': origin})
                         if action_factory else {**allowed_action, 'object_id': objects['private']})
        denied = submit(denied_action)
        assert denied['decision'] == 'deny' and denied['reason'] == 'object_classification_blocks_egress', denied
        assert received == [payloads['public']]
        events = substrate.audit()
        event = next(e for e in events if e['id'] == denied['event_id'])
        assert event['actor'] == 'agent' and event['decision'] == 'deny'
        assert event['action'] == {'kind': 'object.publish',
            'object_id': objects['private'], 'destination_sha256': digest(origin)}
        assert not any(e['action'].get('request_event_id') == event['id'] for e in events)
        receipt = {'result': 'PASS', 'case': 'private_object_publication',
            'model_generated': getattr(action_factory, 'model_generated', False), 'isolated_worker_proof': False,
            'executor': 'substrate.object.publish -> network_adapter.fetch',
            'request_sha256': digest(denied_action), 'public_deliveries': 1,
            'private_deliveries': 0, 'exact_public_content_verified': True,
            'denial': denied, 'audit_receipt': event}
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps({'result': 'PASS', 'receipt': str(directory / 'receipt.json')}))
        return {**receipt, 'receipt': str(directory / 'receipt.json')}
    finally:
        if server: server.should_exit = True
        if api_thread: api_thread.join(10)
        if listener: listener.close()
        receiver.shutdown(); receiver.server_close(); receiver_thread.join(5)
        assert not api_thread or not api_thread.is_alive()
        assert not receiver_thread.is_alive()


def test_real_private_publication_denied():
    run_private_publication()
