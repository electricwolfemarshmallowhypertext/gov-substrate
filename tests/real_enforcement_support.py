"""Actual HTTP substrate server and client, with no substituted transport."""
import json
import socket
import threading
import time
from contextlib import contextmanager
from urllib.request import Request, ProxyHandler, build_opener

import uvicorn
from governance_substrate.substrate import create_app


@contextmanager
def real_api(substrate):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    origin = f'http://127.0.0.1:{listener.getsockname()[1]}'
    server = uvicorn.Server(uvicorn.Config(create_app(substrate), log_level='error'))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    opener = build_opener(ProxyHandler({}))

    def post(path, body, token, session=None):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
        if session: headers['X-Session-Token'] = session
        request = Request(origin + path, data=json.dumps(body).encode(),
                          headers=headers, method='POST')
        with opener.open(request, timeout=15) as response:
            return json.load(response)

    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline, 'API startup failed'
            time.sleep(0.01)
        yield post
    finally:
        server.should_exit = True
        thread.join(10)
        listener.close()
        assert not thread.is_alive(), 'API shutdown failed'


def actor(shared_channels=()):
    return {'network': {'allowed': False, 'destinations': []},
            'filesystem': {'read': False, 'write': False}, 'tools': {},
            'persistence': {'session': True, 'cross_session': False},
            'shared_channels': list(shared_channels), 'data': {'sensitive_access': False}}
