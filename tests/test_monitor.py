from monitor import db, notify, verify, worker

def finding(key, severity='Low'):
    return {'check': 'headers', 'key': key, 'severity': severity, 'title': f'Missing {key}',
            'detail': 'detail', 'fix': 'fix'}

def add(conn, url='https://example.com/'):
    return db.get_site(conn, db.add_site(conn, url, 'Example', 'owner@example.com', '123', 'tok'))

def test_findings_open_once_and_resolve(conn):
    site = add(conn)
    opened, resolved = db.record_scan(conn, site['id'], db.now(), [finding('a'), finding('b')])
    assert len(opened) == 2 and not resolved
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

def test_only_verified_sites_are_due(conn):
    site = add(conn)
    assert db.due_sites(conn) == []
    db.set_verified(conn, site['id'], True)
    assert [s['id'] for s in db.due_sites(conn)] == [site['id']]
    db.schedule_next(conn, db.get_site(conn, site['id']))
    assert db.due_sites(conn) == []

def test_format_changes_sorted_and_readable(conn):
    site = add(conn)
    opened, _ = db.record_scan(conn, site['id'], db.now(), [finding('a', 'Low'), finding('b', 'Critical')])
    subject, text = notify.format_changes(site, db.open_findings(conn, site['id']), [])
    assert subject == '[VulnScan] Example: 2 new, 0 fixed'
    assert text.index('Critical') < text.index('Low')

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

def test_worker_scans_verified_site_and_alerts(fake_site, conn, monkeypatch):
    site = add(conn, fake_site.url)
    fake_site.routes[verify.VERIFY_PATH] = (200, {}, b'tok\n')
    assert verify.check_ownership(site['url'], 'tok')
    db.set_verified(conn, site['id'], True)
    alerts = []
    monkeypatch.setattr(notify, 'notify', lambda s, subject, text: alerts.append(subject) or ['email'])

    worker.run_due(conn)
    assert len(alerts) == 1 and 'new' in alerts[0]
    assert db.get_site(conn, site['id'])['next_scan_at']

    # Nothing changed: a second scan sends nothing
    worker.run_scan(conn, db.get_site(conn, site['id']))
    assert len(alerts) == 1

def test_worker_pauses_site_when_token_removed(fake_site, conn, monkeypatch):
    site = add(conn, fake_site.url)
    db.set_verified(conn, site['id'], True)
    alerts = []
    monkeypatch.setattr(notify, 'notify', lambda s, subject, text: alerts.append(subject) or ['email'])
    worker.run_scan(conn, db.get_site(conn, site['id']))
    assert db.get_site(conn, site['id'])['verified_at'] is None
    assert 'paused' in alerts[0]
    assert fake_site.requests == [verify.VERIFY_PATH]
