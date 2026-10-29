import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('NO_PROXY', '127.0.0.1,localhost')
os.environ['no_proxy'] = os.environ['NO_PROXY']

from scanner import target  # noqa: E402

@pytest.fixture(autouse=True)
def allow_local_targets(monkeypatch):
    monkeypatch.setattr(target, 'ALLOW_PRIVATE', True)

class FakeSite:
    """A tiny local web server whose responses each test can configure."""

    def __init__(self):
        # path -> (status, headers, body bytes)
        self.routes = {}
        self.default = (200, {}, b'<html>home</html>')
        self.requests = []

    def handler(self):
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                site.requests.append(self.path)
                path = self.path.split('?', 1)[0]
                status, headers, body = site.routes.get(path, site.default if path == '/' else (404, {}, b'not found'))
                if callable(body):
                    body = body(self.path)
                self.send_response(status)
                for name, value in headers.items():
                    for v in (value if isinstance(value, list) else [value]):
                        self.send_header(name, v)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        return Handler

@pytest.fixture
def fake_site():
    site = FakeSite()
    server = ThreadingHTTPServer(('127.0.0.1', 0), site.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site.url = f'http://127.0.0.1:{server.server_address[1]}/'
    yield site
    server.shutdown()

@pytest.fixture
def conn(tmp_path):
    from monitor import db
    connection = db.connect(str(tmp_path / 'test.db'))
    db.init_db(connection)
    yield connection
    connection.close()
