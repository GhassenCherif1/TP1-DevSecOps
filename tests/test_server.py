import threading
import time
import urllib.request
import urllib.parse
import json
import sys

import pytest

# Import the server module path
import dsvw


@pytest.fixture(scope="module")
def server_thread():
    # start server in a background thread
    t = threading.Thread(target=dsvw.ThreadingServer((dsvw.LISTEN_ADDRESS, dsvw.LISTEN_PORT), dsvw.ReqHandler).serve_forever, daemon=True)
    t.start()
    # give server a moment to start
    time.sleep(0.5)
    yield
    # shutdown server
    try:
        # create a connection to trigger server shutdown path
        import socket
        s = socket.socket()
        s.connect((dsvw.LISTEN_ADDRESS, dsvw.LISTEN_PORT))
        s.close()
    except Exception:
        pass


def test_root_ok(server_thread):
    url = f"http://{dsvw.LISTEN_ADDRESS}:{dsvw.LISTEN_PORT}/"
    with urllib.request.urlopen(url, timeout=2) as r:
        data = r.read().decode('utf-8')
        assert "Welcome (secure)" in data


def test_users_json(server_thread):
    url = f"http://{dsvw.LISTEN_ADDRESS}:{dsvw.LISTEN_PORT}/users.json"
    with urllib.request.urlopen(url, timeout=2) as r:
        data = r.read().decode('utf-8')
        j = json.loads(data)
        assert isinstance(j, dict)
        assert 'admin' in j
