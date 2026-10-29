import threading
from http.server import ThreadingHTTPServer

import pytest

from demo.vulnerable_site import make_handler
from monitor import checks, verify

@pytest.fixture
def demo():
    servers = []
    def start(fixed):
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler('demo-token', fixed))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f'http://127.0.0.1:{server.server_address[1]}/'
    yield start
    for server in servers:
        server.shutdown()

def test_demo_site_triggers_every_check(demo):
    url = demo(fixed=False)
    assert verify.check_ownership(url, 'demo-token')
    found = {f['check'] for f in checks.run_all(url, active=True)[0]}
    assert {'tls', 'headers', 'cookies', 'disclosure', 'exposed-files', 'sqli', 'xss'} <= found

def test_fixed_demo_site_resolves_most_findings(demo):
    found = {(f['check'], f['key']) for f in checks.run_all(demo(fixed=True), active=True)[0]}
    # Only plain HTTP remains, which a local demo cannot avoid
    assert found == {('tls', 'no-https')}
