"""Real HTTP requests, committed SQLite shared state, and independent observer."""
import json
import secrets
import sqlite3
import sys
import uuid
from pathlib import Path

from governance_substrate.substrate import Substrate, digest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from real_enforcement_support import actor, real_api


def run_shared_channel(action_factory=None):
    directory = ROOT / 'dist/shared-channel-proof' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    tokens = {name: secrets.token_hex(32) for name in ('agent', 'observer')}
    substrate = Substrate(directory / 'substrate.db', {
        'actors': {'agent': actor(['granted']), 'observer': actor(['granted', 'forbidden'])},
        'tokens': {token: name for name, token in tokens.items()},
        'operator_token': secrets.token_hex(32)})
    value = 'shared-write-' + secrets.token_hex(32)
    key = uuid.uuid4().hex
    with real_api(substrate) as post:
        sessions = {name: post('/sessions', {}, token)['session_token']
                    for name, token in tokens.items()}

        def propose(name, action):
            return post('/proposals', {'action': action}, tokens[name], sessions[name])

        def rows():
            with sqlite3.connect(directory / 'substrate.db') as db:
                return db.execute('SELECT namespace,key,value FROM state ORDER BY namespace,key').fetchall()

        allowed_action = {'kind': 'state.write', 'scope': 'shared',
                          'channel': 'granted', 'key': key, 'value': value}
        allowed = propose('agent', allowed_action)
        assert allowed['decision'] == 'allow', allowed
        assert rows() == [('shared:granted', key, json.dumps(value))]
        read = {'kind': 'state.read', 'scope': 'shared', 'channel': 'granted', 'key': key}
        observed = propose('observer', read)
        assert observed['decision'] == 'allow' and observed['value'] == value, observed
        denied_action = (action_factory('write_shared', {'scope': 'shared', 'channel': 'forbidden',
                         'key': key, 'value': value}) if action_factory else
                         {**allowed_action, 'channel': 'forbidden'})
        before = rows()
        denied = propose('agent', denied_action)
        assert denied['decision'] == 'deny' and denied['reason'] == 'shared_channel_disabled', denied
        assert rows() == before
        missing = propose('observer', {**read, 'channel': 'forbidden'})
        assert missing['decision'] == 'allow' and missing['value'] is None, missing
        event = next(e for e in substrate.audit() if e['id'] == denied['event_id'])
        assert event['actor'] == 'agent' and event['decision'] == 'deny'
        assert event['action'] == denied_action
        receipt = {'result': 'PASS', 'case': 'ungranted_shared_channel_write',
            'executor': 'Substrate.propose SQLite state INSERT/UPDATE',
            'model_generated': getattr(action_factory, 'model_generated', False), 'isolated_worker_proof': False,
            'request_sha256': digest(denied_action), 'allowed_committed_writes': 1,
            'observer_verified_value': True, 'ungranted_state_changes': 0,
            'observer_forbidden_value': None, 'denial': denied, 'audit_receipt': event}
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps({'result': 'PASS', 'receipt': str(directory / 'receipt.json')}))

    return {**receipt, 'receipt': str(directory / 'receipt.json')}


def test_real_ungranted_shared_write_denied():
    run_shared_channel()
