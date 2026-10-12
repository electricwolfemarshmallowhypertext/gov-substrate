"""Isolated native-tool worker; only the Python standard library and transport."""
import base64
import json
import os
import sys

if __package__:
    from .agent_transport import SubstrateClient, canonical
else:
    from agent_transport import SubstrateClient, canonical


def worker():
    client = SubstrateClient(os.environ.get('GOV_SUBSTRATE_SOCKET', '/ipc/agent/substrate.sock'),
                             os.environ['AGENT_TOKEN'])
    client.start_session()
    print(canonical({'ready': True}), flush=True)
    for line in sys.stdin:
        try:
            command = json.loads(line)
            if command.get('op') == 'stop':
                return
            if command.get('op') == 'prepare':
                result = client.api('POST', '/proposals', {'action': {
                    'kind': 'generation.prepare', 'input_ids': [command['input_id']],
                    'provider': command['provider'], 'provider_request': command['profile']}})
            elif command.get('op') == 'model_output':
                source = client.execute({'kind': 'object.read', 'object_id': command['object_id']})
                if source['result']['decision'] != 'allow':
                    raise RuntimeError('model_output_read_denied')
                response = json.loads(base64.b64decode(source['result']['content_base64'], validate=True))
                message = response['choices'][0]['message']
                calls = message.get('tool_calls') or []
                if type(calls) is not list or len(calls) > 8:
                    raise RuntimeError('native_tool_batch_limit')
                # Return the first tool result before accepting any dependent action.
                capture_only = command.get('capture_only', False)
                if type(capture_only) is not bool:
                    raise ValueError('invalid_capture_option')
                executed = [client.native(calls[0])] if calls and not capture_only else []
                deferred = [client.defer(call) for call in calls[1:]]
                result = {'message': message, 'calls': executed, 'deferred_calls': deferred,
                          'native_requests': calls[:1] if capture_only else [],
                          'governed_output_read': source}
            elif command.get('op') == 'native':
                result = client.native(command['call'])
            else:
                raise ValueError('unsupported_agent_command')
        except Exception as exc:
            client._failure('WORKER', '/command', 'command_failed', detail=str(exc))
            result = {'outcome': 'failed', 'reason': 'worker_command_failed',
                      'detail': client._sanitize(str(exc))}
        print(canonical(result), flush=True)


if __name__ == '__main__':
    worker()
