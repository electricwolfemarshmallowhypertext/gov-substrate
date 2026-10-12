"""One real SMTP execution; the identical grant cannot cause a second effect."""
import json
import secrets
import sqlite3
import sys
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path

from governance_substrate.substrate import Substrate, digest
from governance_substrate.tool_adapter import SMTPSendEmailAdapter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from real_enforcement_support import actor, real_api
from smtp_sink import LocalSMTPSink


def run_grant_replay(action_factory=None):
    directory = ROOT / 'dist/grant-replay-proof' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    token = secrets.token_hex(32)
    caps = actor()
    caps['tools'] = {'send_email': True}
    action = {'kind': 'tool.invoke', 'tool': 'send_email', 'call_id': uuid.uuid4().hex,
        'arguments': {'recipients': ['recipient@example.test'], 'subject': 'Grant replay control',
                      'body': 'replay-canary-' + secrets.token_hex(32)}}
    if action_factory:
        action = action_factory('send_email', action['arguments'])
    with LocalSMTPSink() as sink:
        substrate = Substrate(directory / 'substrate.db', {
            'actors': {'agent': caps}, 'tokens': {token: 'agent'},
            'operator_token': secrets.token_hex(32)}, tool_adapters={
                'send_email': SMTPSendEmailAdapter('127.0.0.1', sink.port, 'operator@example.test')})
        with real_api(substrate) as post:
            session = post('/sessions', {}, token)['session_token']
            authorization = post('/authorizations', {'action': action}, token, session)
            assert authorization['decision'] == 'allow', authorization
            assert sink.messages == [] and sink.mail_commands == 0
            execution = {'action': action, 'execution_token': authorization['execution_token']}
            first = post('/executions', execution, token, session)
            assert first['decision'] == 'allow' and first['outcome'] == 'succeeded', first
            assert len(sink.messages) == sink.mail_commands == 1
            message = BytesParser(policy=policy.default).parsebytes(sink.messages[0]['data'])
            assert message.get_content().strip() == action['arguments']['body']
            assert message['Subject'] == action['arguments']['subject']
            assert sink.messages[0]['recipients'] == action['arguments']['recipients']
            second = post('/executions', execution, token, session)
            assert second['decision'] == 'deny' and second['reason'] == 'execution_grant_reused', second
            assert len(sink.messages) == sink.mail_commands == 1
            events = substrate.audit()
            event = next(e for e in events if e['id'] == second['event_id'])
            assert event['actor'] == 'agent' and event['decision'] == 'deny'
            assert event['action'] == {'kind': 'tool.invoke', 'tool': 'send_email',
                'call_id': action['call_id'], 'arguments_sha256': digest(action['arguments'])}
            assert not any(e['action'].get('request_event_id') == event['id'] for e in events)
            with sqlite3.connect(directory / 'substrate.db') as db:
                statuses = db.execute('SELECT status FROM execution_grants').fetchall()
            assert statuses == [('used',)], statuses
            receipt = {'result': 'PASS', 'case': 'execution_grant_replay',
                'executor': 'SMTPSendEmailAdapter.execute', 'model_generated': getattr(action_factory, 'model_generated', False),
                'isolated_worker_proof': False, 'request_sha256': digest(action),
                'first_smtp_deliveries': 1, 'replay_smtp_deliveries': 0,
                'replay_smtp_mail_commands': 0, 'exact_message_verified': True,
                'grant_status': 'used', 'denial': second, 'audit_receipt': event}
            (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
            print(json.dumps({'result': 'PASS', 'receipt': str(directory / 'receipt.json')}))

    return {**receipt, 'receipt': str(directory / 'receipt.json')}


def test_real_grant_replay_has_no_second_effect():
    run_grant_replay()
