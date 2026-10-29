import sqlite3

import pytest

from monitor import config, db, notify, verify, worker

def finding(key, severity='Low'):
    return {'check': 'headers', 'key': key, 'severity': severity, 'title': f'Missing {key}',
            'detail': 'detail', 'fix': 'fix', 'evidence': f'GET / without {key}'}

def add(conn, url='https://example.com/', authorise=True):
    site_id = db.add_site(conn, url, 'Example', 'owner@example.com', '123', 'tok')
    if authorise:
        db.set_authorisation(conn, site_id, '2026-10-29', 'AUTH-1', '', False)
    return db.get_site(conn, site_id)

@pytest.fixture
def messages(monkeypatch):
    """Capture every outgoing message as (recipient email, subject, text)."""
    sent = []
    def fake_notify(site, subject, text):
        sent.append((site['owner_email'], subject, text))
        return ['email']
    monkeypatch.setattr(notify, 'notify', fake_notify)
    monkeypatch.setattr(config, 'ADMIN_EMAIL', 'analyst@vulnscan.test')
    return sent

def test_findings_open_once_and_resolve(conn):
    site = add(conn)
    opened, resolved = db.record_scan(conn, site['id'], db.now(), [finding('a'), finding('b')])
    assert len(opened) == 2 and not resolved
    assert {r['status'] for r in opened} == {'pending'}
    opened, resolved = db.record_scan(conn, site['id'], db.now(), [finding('a'), finding('b')])
    assert not opened and not resolved
    opened, resolved = db.record_scan(conn, site['id'], db.now(), [finding('a')])
    assert not opened and [r['title'] for r in resolved] == ['Missing b']
    assert [r['title'] for r in db.open_findings(conn, site['id'])] == ['Missing a']

def test_failed_scan_does_not_resolve(conn):
    site = add(conn)
    db.record_scan(conn, site['id'], db.now(), [finding('a')])
    opened, resolved = db.record_scan(conn, site['id'], db.now(), [], error='timeout')
    assert not resolved
    assert db.recent_scans(conn, site['id'])[0]['status'] == 'failed'

def test_only_verified_and_authorised_sites_are_due(conn):
    site = add(conn, authorise=False)
    db.set_verified(conn, site['id'], True)
    assert db.due_sites(conn) == []
    db.set_authorisation(conn, site['id'], '2026-10-29', 'AUTH-1', '', False)
    assert [s['id'] for s in db.due_sites(conn)] == [site['id']]
    db.schedule_next(conn, db.get_site(conn, site['id']))
    assert db.due_sites(conn) == []

def test_migrates_old_database(tmp_path):
    path = str(tmp_path / 'old.db')
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE sites (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, name TEXT NOT NULL, owner_email TEXT,
            telegram_chat_id TEXT, verify_token TEXT NOT NULL, verified_at TEXT, interval_hours INTEGER NOT NULL,
            next_scan_at TEXT, last_scan_at TEXT, last_digest_at TEXT, created_at TEXT NOT NULL);
        CREATE TABLE findings (id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
            check_name TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
            fix TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT);
        INSERT INTO sites VALUES (1, 'https://a.test/', 'A', NULL, NULL, 't', NULL, 6, NULL, NULL, NULL, 'x');
        INSERT INTO findings VALUES (1, 1, 'fp', 'headers', 'Low', 't', 'd', 'f', 'x', 'x', NULL);
    """)
    old.commit()
    old.close()
    conn = db.connect(path)
    db.init_db(conn)
    assert db.get_site(conn, 1)['active_tests'] == 0
    assert db.get_finding(conn, 1)['status'] == 'pending'

def test_format_changes_sorted_with_note_and_evidence(conn):
    site = add(conn)
    db.record_scan(conn, site['id'], db.now(), [finding('a', 'Low'), finding('b', 'Critical')])
    row = db.open_findings(conn, site['id'])[0]
    db.review_finding(conn, row['id'], 'approved', 'Your checkout page is affected')
    subject, text = notify.format_changes(site, db.open_findings(conn, site['id']), [])
    assert subject == '[VulnScan] Example: 2 new, 0 fixed'
    assert text.index('Critical') < text.index('Low')
    assert 'Analyst note: Your checkout page is affected' in text
    assert 'Evidence: GET / without b' in text

def test_notify_sends_telegram(monkeypatch, conn):
    site = add(conn)
    sent = {}
    monkeypatch.setattr(notify.config, 'TELEGRAM_BOT_TOKEN', 'bot-token')
    class Response:
        def raise_for_status(self):
            pass
    def fake_post(url, json, timeout):
        sent['url'], sent['json'] = url, json
        return Response()
    monkeypatch.setattr(notify.requests, 'post', fake_post)
    assert notify.notify(site, 'subject', 'body') == ['telegram']
    assert sent['url'].endswith('/botbot-token/sendMessage')
    assert sent['json']['chat_id'] == '123'

def test_notify_survives_channel_failure(monkeypatch, conn):
    site = add(conn)
    monkeypatch.setattr(notify, 'send_email', lambda *a: (_ for _ in ()).throw(OSError('smtp down')))
    monkeypatch.setattr(notify, 'send_telegram', lambda *a: True)
    assert notify.notify(site, 's', 't') == ['telegram']

def verified_site(conn, fake_site):
    site = add(conn, fake_site.url)
    fake_site.routes[verify.VERIFY_PATH] = (200, {}, b'tok\n')
    db.set_verified(conn, site['id'], True)
    return db.get_site(conn, site['id'])

def test_review_flow_client_only_hears_approved_findings(fake_site, conn, messages):
    site = verified_site(conn, fake_site)
    worker.run_due(conn)
    # Only the analyst hears about new findings
    assert [m[0] for m in messages] == ['analyst@vulnscan.test']
    assert 'Review needed' in messages[0][1]

    pending = db.open_findings(conn, site['id'], 'pending')
    db.review_finding(conn, pending[0]['id'], 'approved', 'Matters for you')
    for row in pending[1:]:
        db.review_finding(conn, row['id'], 'dismissed')
    worker.notify_client(conn, site)
    assert messages[-1][0] == 'owner@example.com'
    assert '1 new' in messages[-1][1] and 'Matters for you' in messages[-1][2]

    # A rescan with nothing changed sends nothing to anyone
    count = len(messages)
    worker.run_scan(conn, db.get_site(conn, site['id']))
    assert len(messages) == count
    # Nothing left to send either
    assert worker.notify_client(conn, site) == []

def test_client_told_when_reported_issue_is_fixed(fake_site, conn, messages):
    fake_site.default = (200, {'X-Powered-By': 'PHP/7.2.1'}, b'<html></html>')
    site = verified_site(conn, fake_site)
    worker.run_scan(conn, site)
    for row in db.open_findings(conn, site['id'], 'pending'):
        db.review_finding(conn, row['id'], 'approved')
    worker.notify_client(conn, site)

    fake_site.default = (200, {}, b'<html></html>')
    worker.run_scan(conn, db.get_site(conn, site['id']))
    assert messages[-1][0] == 'owner@example.com'
    assert '0 new, 1 fixed' in messages[-1][1]

def test_auto_approve_when_review_disabled(fake_site, conn, messages, monkeypatch):
    monkeypatch.setattr(config, 'REVIEW_REQUIRED', False)
    site = verified_site(conn, fake_site)
    worker.run_scan(conn, site)
    assert [m[0] for m in messages] == ['owner@example.com']
    assert not db.open_findings(conn, site['id'], 'pending')

def test_worker_pauses_site_when_token_removed(fake_site, conn, messages):
    site = add(conn, fake_site.url)
    db.set_verified(conn, site['id'], True)
    worker.run_scan(conn, db.get_site(conn, site['id']))
    assert db.get_site(conn, site['id'])['verified_at'] is None
    assert 'paused' in messages[0][1]
    assert fake_site.requests == [verify.VERIFY_PATH]

def test_test_alert_cli_reports_missing_config(monkeypatch, capsys):
    monkeypatch.setattr(notify.config, 'TELEGRAM_BOT_TOKEN', None)
    monkeypatch.setattr('sys.argv', ['notify', '--telegram', '123'])
    with pytest.raises(SystemExit) as exit_info:
        notify.main()
    assert exit_info.value.code == 1
    assert 'TELEGRAM_BOT_TOKEN is not set' in capsys.readouterr().out
