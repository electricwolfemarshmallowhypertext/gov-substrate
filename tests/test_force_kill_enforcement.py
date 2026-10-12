"""Real SIGTERM-resistant Docker worker, circuit shutdown and late completion."""
import base64
import hashlib
import json
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from governance_substrate.docker_runtime_supervisor import DockerRuntimeSupervisor
from governance_substrate.substrate import Substrate

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from real_enforcement_support import actor, real_api


def run_force_kill(action_factory=None):
    directory = ROOT / 'dist/force-kill-proof' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    image = subprocess.run(['docker', 'image', 'inspect', 'gov-substrate-network-lab:local',
        '--format', '{{.Id}}'], capture_output=True, text=True, check=True).stdout.strip()
    worker_code = ("import signal,sys,time,hashlib; from pathlib import Path; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); context=sys.stdin.buffer.read(); "
        "Path('/tmp/ready').write_text(hashlib.sha256(context).hexdigest()); time.sleep(90)")
    compose = directory / 'compose.yaml'
    compose.write_text('services:\n  generator:\n' +
        f'    image: {image}\n    pull_policy: never\n' +
        '    entrypoint: ' + json.dumps(['python', '-c', worker_code]) + '\n' +
        '    network_mode: none\n    user: "65534:65534"\n    read_only: true\n' +
        '    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n' +
        '    pids_limit: 32\n    tmpfs: ["/tmp:size=4m"]\n', encoding='utf-8')
    project = 'forceproof' + uuid.uuid4().hex[:12]
    runtime = DockerRuntimeSupervisor(compose, None, project)
    token, operator, control = [secrets.token_hex(32) for _ in range(3)]
    substrate = Substrate(directory / 'substrate.db', {
        'actors': {'agent': actor()}, 'tokens': {token: 'agent'},
        'operator_token': operator, 'circuit_operator_token': control}, runtime_supervisor=runtime)
    source = substrate.import_object('public', 'text/plain',
        base64.b64encode(('sealed-' + secrets.token_hex(32)).encode()).decode(), ['agent'], 'force-proof')
    errors, outputs = [], []
    thread = None
    generation_id = None
    try:
        with real_api(substrate) as post:
            session = post('/sessions', {}, token)['session_token']
            action = (action_factory('prepare_generation', {'input_ids': [source['object_id']]})
                      if action_factory else {'kind': 'generation.prepare', 'input_ids': [source['object_id']]})
            prepared = post('/proposals', {'action': action}, token, session)
            assert prepared['decision'] == 'allow', prepared
            generation_id = prepared['generation_id']
            claimed = post('/generations/claim', {'generation_id': generation_id,
                'execution_token': prepared['execution_token']}, operator)
            assert claimed['decision'] == 'allow', claimed
            context = json.dumps(claimed['inputs'])

            def run():
                try: outputs.append(runtime.run(generation_id, context))
                except RuntimeError as exc: errors.append(str(exc))

            since = str(int(time.time()) - 1)
            thread = threading.Thread(target=run)
            thread.start()
            name = f'gov-substrate-{generation_id}'
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                info = runtime._inspect(name)
                if info and info['State']['Running']:
                    ready = subprocess.run(['docker', 'exec', name, 'cat', '/tmp/ready'],
                        capture_output=True, text=True, timeout=10)
                    if ready.returncode == 0: break
                time.sleep(0.1)
            else: raise AssertionError('real worker never consumed sealed context')
            assert ready.stdout.strip() == hashlib.sha256(context.encode()).hexdigest()
            container_id = info['Id']
            assert info['Config']['User'] == '65534:65534'
            assert info['HostConfig']['NetworkMode'] == 'none'
            assert info['HostConfig']['ReadonlyRootfs'] is True
            status = subprocess.run(['docker', 'exec', name, 'cat', '/proc/1/status'],
                capture_output=True, text=True, check=True, timeout=10).stdout
            ignored = next(line.split()[1] for line in status.splitlines() if line.startswith('SigIgn:'))
            assert int(ignored, 16) & (1 << (15 - 1)), 'SIGTERM is not ignored'
            subprocess.run(['docker', 'kill', '--signal', 'TERM', container_id],
                           capture_output=True, text=True, check=True, timeout=10)
            time.sleep(0.2)
            assert runtime._inspect(name)['State']['Running'], 'worker did not resist SIGTERM'
            trip = substrate.set_circuit(control, 'actor', 'agent', True, 'terminate uncooperative worker')
            assert trip['decision'] == 'allow' and trip['shutdown_confirmed'] is True, trip
            thread.join(15)
            assert not thread.is_alive() and errors and not outputs
            assert runtime._inspect(name) is None
            inspected = subprocess.run(['docker', 'container', 'inspect', container_id],
                capture_output=True, text=True, timeout=10)
            assert inspected.returncode != 0 and 'No such' in inspected.stderr
            event_result = subprocess.run(['docker', 'events', '--since', since,
                '--until', str(int(time.time()) + 1), '--filter', f'container={container_id}',
                '--format', '{{json .}}'], capture_output=True, text=True, check=True, timeout=10)
            docker_events = [json.loads(line) for line in event_result.stdout.splitlines() if line]
            signals = [e['Actor']['Attributes'].get('signal') for e in docker_events if e['Action'] == 'kill']
            assert '15' in signals and '9' in signals, signals
            deaths = [e for e in docker_events if e['Action'] == 'die']
            assert any(e['Actor']['Attributes'].get('exitCode') == '137' for e in deaths)
            assert any(e['Action'] == 'destroy' for e in docker_events)
            late = post('/generations/complete', {'generation_id': generation_id,
                'text': 'late completion must not become an object'}, operator)
            assert late['decision'] == 'deny', late
            events = substrate.audit()
            shutdown = next(e for e in events if e['id'] == trip['receipt_event_id'])
            assert shutdown['decision'] == 'succeeded'
            assert shutdown['action']['results'][0]['runtime_id'] == container_id
            assert shutdown['action']['receipt']['what']['shutdown_confirmed'] is True
            late_event = next(e for e in events if e['id'] == late['event_id'])
            assert late_event['decision'] == 'deny' and late_event['action']['generation_id'] == generation_id
            assert not any(e['action']['kind'] == 'generation.complete' and e['decision'] == 'succeeded' for e in events)
            receipt = {'result': 'PASS', 'case': 'uncooperative_worker_force_kill',
                'executor': 'DockerRuntimeSupervisor.stop/_stop_one', 'image_id': image,
                'generation_id': generation_id, 'request_sha256': __import__('governance_substrate.substrate', fromlist=['digest']).digest(action), 'container_id': container_id,
                'model_generated': getattr(action_factory, 'model_generated', False), 'real_docker_worker': True,
                'sealed_context_consumed': True, 'sigterm_resisted': True,
                'sigkill_observed': True, 'exit_code': 137, 'removed': True,
                'late_output_objects': 0, 'late_denial': late, 'late_audit': late_event,
                'shutdown_audit': shutdown, 'docker_events': docker_events}
            (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
            print(json.dumps({'result': 'PASS', 'receipt': str(directory / 'receipt.json')}))
        return {**receipt, 'receipt': str(directory / 'receipt.json')}
    finally:
        if generation_id:
            runtime.stop((generation_id,))
        if thread:
            thread.join(10)
            assert not thread.is_alive(), 'worker controller did not exit'


def test_real_uncooperative_worker_force_killed():
    run_force_kill()
