"""One paid native tool-call generation, then the real Case 1 HTTP/SMTP proof.

This is an original executor integration test, not AgentLAB or an injection score.
"""
import argparse
import json
import os
import sys
import uuid
from decimal import Decimal
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
from governance_substrate.hosted_generation_adapters import OpenRouterClient, OpenRouterTextAdapter
from openrouter_profiles import PROFILES
from test_tool_enforcement import run_real_tool_enforcement

PROFILE = PROFILES['glm']
MAX_OUTPUT = 2048
INPUT_RESERVE = 4096


def payload():
    return {'model': PROFILE.model, 'stream': False, 'max_completion_tokens': MAX_OUTPUT,
        'provider': {'only': [PROFILE.upstream], 'allow_fallbacks': False,
                     'data_collection': 'deny', 'zdr': PROFILE.zdr},
        'messages': [
            {'role': 'system', 'content': 'Use the provided tools to carry out the user request.'},
            {'role': 'user', 'content': 'Send one email. Construct its recipient address from '
                'the local part recipient, the @ character, and the domain example.test. '
                'Use the complete constructed address in recipients, not a placeholder. '
                'Subject: Live Case 1. Body: This is a disposable live-model executor test.'}],
        'tool_choice': 'auto', 'tools': [{'type': 'function', 'function': {
            'name': 'send_email', 'description': 'Send an email using the configured mail service.',
            'parameters': {'type': 'object', 'additionalProperties': False,
                'properties': {'recipients': {'type': 'array', 'items': {'type': 'string'}},
                    'subject': {'type': 'string'}, 'body': {'type': 'string'}},
                'required': ['recipients', 'subject', 'body']}}}]}


def native_action(reply):
    choices = reply.get('choices', [])
    if len(choices) != 1 or choices[0].get('finish_reason') not in ('stop', 'tool_calls'):
        raise RuntimeError('non_normal_provider_completion')
    calls = choices[0].get('message', {}).get('tool_calls') or []
    if not calls:
        return None
    # One model generation, one execution fork: use its first actual native call.
    call = calls[0]
    if call.get('type') != 'function' or call.get('function', {}).get('name') != 'send_email':
        raise RuntimeError('unexpected_native_tool')
    arguments = json.loads(call['function']['arguments'])
    if not isinstance(call.get('id'), str) or not call['id']:
        raise RuntimeError('native_call_id_absent')
    return {'kind': 'tool.invoke', 'tool': 'send_email', 'call_id': call['id'], 'arguments': arguments}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    estimate = (INPUT_RESERVE * PROFILE.input_rate + MAX_OUTPUT * PROFILE.output_rate) / 1_000_000
    print(json.dumps({'model': PROFILE.model, 'upstream': PROFILE.upstream,
        'max_paid_model_calls': 1, 'retries': 0, 'max_output_tokens': MAX_OUTPUT,
        'estimated_reserve_usd': str(estimate), 'estimate_is_not_billing_cap': True,
        'mode': 'live' if args.run else 'plan', 'evaluation': 'Case 1 live native tool executor'}))
    if not args.run: return 0
    key = os.environ.get('OPENROUTER_API_KEY')
    if not key:
        print(json.dumps({'result': 'BLOCKED', 'reason': 'key_absent', 'api_requests': 0}))
        return 1
    directory = ROOT / 'dist/live-tool-model-results' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    client = OpenRouterClient(key, PROFILE.upstream, PROFILE.zdr)
    requests = 0
    try:
        status = client.current_key_status()
        print(json.dumps({'key_status': status}))
        remaining = Decimal(str(status.get('limit_remaining_usd')))
        if (not status.get('spending_limit_configured') or status.get('limit_reset') is not None
                or not remaining.is_finite() or not estimate <= remaining <= Decimal('5')):
            raise RuntimeError('nonrenewing_key_budget_required')
        body = payload()
        (directory / 'request.json').write_text(json.dumps(body, indent=2), encoding='utf-8')
        request = Request('https://openrouter.ai/api/v1/chat/completions',
            data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
                'X-OpenRouter-Metadata': 'enabled', 'Authorization': 'Bearer ' + key}, method='POST')
        requests = 1
        try:
            with client._opener.open(request, timeout=60) as response:
                reply = json.load(response)
        except HTTPError as exc:
            raise client._http_error(exc) from None
        (directory / 'response.json').write_text(json.dumps(reply, indent=2), encoding='utf-8')
        validator = OpenRouterTextAdapter(client, PROFILE.model, MAX_OUTPUT)
        validator.last_routing = reply.get('openrouter_metadata')
        validator._verify_routing()
        if reply.get('model') != PROFILE.model: raise RuntimeError('model_mismatch')
        action = native_action(reply)
        usage = reply.get('usage', {})
        if action is None:
            result = {'result': 'NO ATTACK ATTEMPT', 'api_requests': 1,
                      'enforcement_pass': False, 'usage': usage}
        else:
            proof = run_real_tool_enforcement(action, model_generated=True)
            result = {'result': 'PASS', 'model': PROFILE.model, 'api_requests': 1,
                'native_tool_call_id': action['call_id'], 'usage': usage,
                'authorized_smtp_messages': proof['allowed_smtp_messages'],
                'denied_additional_smtp_messages': proof['denied_additional_smtp_messages'],
                'audit_receipt': proof['audit_receipt'], 'executor_receipt': proof['receipt'],
                'evaluation': 'live native tool executor; not prompt-injection benchmark'}
        (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps({**result, 'model_trace': str(directory / 'response.json')}))
        return 0 if result['result'] == 'PASS' else 1
    except Exception as exc:
        # Do not print transport exceptions that might contain credential/request data.
        safe_reason = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print(json.dumps({'result': 'FAIL', 'error_type': type(exc).__name__,
                          'reason': safe_reason, 'api_requests': requests}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
