from monitor import checks

def keys(findings):
    return {(f['check'], f['key']) for f in findings}

def test_plain_http_site_is_flagged(fake_site):
    findings, error = checks.run_all(fake_site.url)
    assert error is None
    assert ('tls', 'no-https') in keys(findings)

def test_missing_headers_and_disclosure(fake_site):
    fake_site.default = (200, {'X-Powered-By': 'PHP/7.2.1'}, b'<html>home</html>')
    found = keys(checks.run_all(fake_site.url)[0])
    assert ('headers', 'content-security-policy') in found
    assert ('headers', 'x-frame-options') in found
    # HSTS only matters over HTTPS
    assert ('headers', 'strict-transport-security') not in found
    assert ('disclosure', 'x-powered-by') in found

def test_good_headers_not_flagged(fake_site):
    fake_site.default = (200, {
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
    }, b'<html>home</html>')
    found = keys(checks.run_all(fake_site.url)[0])
    assert not {k for k in found if k[0] == 'headers'}

def test_insecure_cookie(fake_site):
    fake_site.default = (200, {'Set-Cookie': ['session=abc; Path=/', 'ok=1; HttpOnly']}, b'<html></html>')
    found = keys(checks.run_all(fake_site.url)[0])
    assert ('cookies', 'session') in found
    assert ('cookies', 'ok') not in found

def test_exposed_env_detected_without_leaking_contents(fake_site):
    fake_site.routes['/.env'] = (200, {}, b'DB_PASSWORD=hunter2\nAPP_KEY=secret\n')
    findings = checks.run_all(fake_site.url)[0]
    env = [f for f in findings if f['key'] == '/.env']
    assert env and env[0]['severity'] == 'Critical'
    assert 'hunter2' not in str(findings)

def test_soft_404_is_not_an_exposed_file(fake_site):
    page = (200, {}, b'<html>Page not found</html>')
    for path in ('/.env', '/.git/HEAD', '/.git/config', '/backup.sql'):
        fake_site.routes[path] = page
    assert not [f for f in checks.run_all(fake_site.url)[0] if f['check'] == 'exposed-files']

def test_sqli_and_xss(fake_site):
    def page(path):
        body = 'You have an error in your SQL syntax' if '%27' in path and 'id=' in path else ''
        if 'q=' in path:
            from urllib.parse import urlparse, parse_qs
            body += parse_qs(urlparse(path).query).get('q', [''])[0]
        return body.encode()
    fake_site.default = (200, {}, page)
    found = keys(checks.run_all(fake_site.url)[0])
    assert ('sqli', 'id-param') in found
    assert ('xss', 'q-param') in found

def test_redirect_to_blocked_host_is_refused(fake_site, monkeypatch):
    from scanner import target
    fake_site.default = (302, {'Location': 'http://169.254.169.254/latest/meta-data/'}, b'')
    calls = []
    real = target.validate_target
    def guarded(url):
        calls.append(url)
        return 'blocked' if '169.254' in url else real(url)
    monkeypatch.setattr(checks, 'validate_target', guarded)
    findings, error = checks.run_all(fake_site.url)
    assert error and 'Refusing' in error
    assert any('169.254' in c for c in calls)

def test_unreachable_site_reports_error():
    findings, error = checks.run_all('http://127.0.0.1:9/')
    assert error is not None
