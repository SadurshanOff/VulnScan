import re

import pytest

@pytest.fixture
def client(tmp_path, monkeypatch):
    from monitor import config
    monkeypatch.setattr(config, 'DB_PATH', str(tmp_path / 'app.db'))
    monkeypatch.setattr(config, 'ADMIN_PASSWORD', 'pw')
    import app
    app.app.config['TESTING'] = True
    return app.app.test_client()

def token(client, path):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).data.decode()).group(1)

def login(client):
    return client.post('/login', data={'password': 'pw', 'csrf_token': token(client, '/login')})

def test_pages_require_login(client):
    for path in ('/', '/sites', '/results', '/guidance'):
        assert client.get(path).status_code == 302

def test_post_without_csrf_rejected(client):
    assert client.post('/login', data={'password': 'pw'}).status_code == 400

def test_wrong_password(client):
    r = client.post('/login', data={'password': 'nope', 'csrf_token': token(client, '/login')})
    assert b'Wrong password' in r.data

def test_add_and_verify_site(client, fake_site):
    login(client)
    t = token(client, '/sites')
    r = client.post('/sites', data={'csrf_token': t, 'name': 'Acme', 'url': fake_site.url,
                                    'owner_email': 'o@acme.test'})
    assert r.status_code == 302
    page = client.get(r.headers['Location']).data.decode()
    verify_token = re.search(r'<pre>([^<]+)</pre>', page).group(1)
    assert 'Awaiting verification' in page

    r = client.post(r.headers['Location'] + '/verify', data={'csrf_token': t}, follow_redirects=True)
    assert b'Verification file not found' in r.data

    from monitor import verify
    fake_site.routes[verify.VERIFY_PATH] = (200, {}, verify_token.encode())
    r = client.post('/sites/1/verify', data={'csrf_token': t}, follow_redirects=True)
    assert b'Monitoring since' in r.data

def test_add_site_needs_contact(client, fake_site):
    login(client)
    r = client.post('/sites', data={'csrf_token': token(client, '/sites'), 'name': 'Acme', 'url': fake_site.url})
    assert b'Add an email address or a Telegram chat id' in r.data
