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

def test_full_service_flow(client, fake_site, monkeypatch):
    from monitor import notify, verify
    sent = []
    monkeypatch.setattr(notify, 'notify', lambda site, subject, text: sent.append(subject) or ['email'])
    fake_site.default = (200, {'X-Powered-By': 'PHP/7.2.1'}, b'<html></html>')

    login(client)
    t = token(client, '/sites')
    r = client.post('/sites', data={'csrf_token': t, 'name': 'Acme', 'url': fake_site.url,
                                    'owner_email': 'o@acme.test'})
    assert r.status_code == 302
    page = client.get('/sites/1').data.decode()
    verify_token = re.search(r'<pre>([^<]+)</pre>', page).group(1)
    assert 'awaiting verification' in page and 'scanning is blocked' in page

    r = client.post('/sites/1/verify', data={'csrf_token': t}, follow_redirects=True)
    assert b'Verification file not found' in r.data
    fake_site.routes[verify.VERIFY_PATH] = (200, {}, verify_token.encode())
    r = client.post('/sites/1/verify', data={'csrf_token': t}, follow_redirects=True)
    assert b'verified 20' in r.data

    # No scan without a recorded authorisation
    r = client.post('/sites/1/scan', data={'csrf_token': t}, follow_redirects=True)
    assert b'written authorisation' in r.data
    r = client.post('/sites/1/authorisation', data={'csrf_token': t, 'authorised_on': '2026-10-29',
                                                    'authorisation_ref': 'AUTH-001'}, follow_redirects=True)
    assert b'passive checks only' in r.data

    r = client.post('/sites/1/scan', data={'csrf_token': t}, follow_redirects=True)
    assert b'Scan finished' in r.data and b'Waiting for your review (0)' not in r.data
    assert all('Review needed' in s for s in sent)

    from monitor import db
    conn = db.connect()
    pending = db.open_findings(conn, 1, 'pending')
    powered = [f for f in pending if f['title'].startswith('X-Powered-By')][0]
    client.post(f'/findings/{powered["id"]}/review', data={'csrf_token': t, 'status': 'approved',
                                                           'analyst_note': 'Hides your PHP version'})
    r = client.post('/sites/1/notify', data={'csrf_token': t}, follow_redirects=True)
    assert b'sent to the client' in r.data
    assert sent[-1] == '[VulnScan] Acme: 1 new, 0 fixed'

    report = client.get('/sites/1/report').data.decode()
    assert 'X-Powered-By header reveals technology' in report
    assert 'Hides your PHP version' in report and 'AUTH-001' in report
    # Pending findings never appear in the client report
    assert 'Missing Content-Security-Policy header' not in report

def test_add_site_needs_contact(client, fake_site):
    login(client)
    r = client.post('/sites', data={'csrf_token': token(client, '/sites'), 'name': 'Acme', 'url': fake_site.url})
    assert b'Add an email address or a Telegram chat id' in r.data
