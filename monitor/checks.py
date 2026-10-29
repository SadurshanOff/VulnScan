"""Low-impact checks run against a verified site on every scheduled scan.

Each check returns a list of findings: dicts with check, key, severity, title,
detail and fix. `key` must be stable across scans so a finding is only
alerted once and can be marked resolved when it disappears.
"""
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

from monitor import config
from scanner import sql_injection, xss
from scanner.target import validate_target

TIMEOUT = 10
MAX_BODY = 64 * 1024

def finding(check, key, severity, title, detail, fix, evidence=''):
    return {'check': check, 'key': key, 'severity': severity, 'title': title, 'detail': detail, 'fix': fix,
            'evidence': evidence}

def _observed(response):
    return f'GET {response.url} returned HTTP {response.status_code}'

def safe_get(url, max_redirects=5):
    """GET a URL, following redirects only to hosts that pass validate_target."""
    for _ in range(max_redirects + 1):
        error = validate_target(url)
        if error:
            raise requests.RequestException(f'Refusing to fetch {url}: {error}')
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False,
                                headers={'User-Agent': config.USER_AGENT})
        if response.is_redirect and 'Location' in response.headers:
            url = urljoin(url, response.headers['Location'])
            continue
        return response
    raise requests.RequestException(f'Too many redirects for {url}')

def check_tls(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return [finding('tls', 'no-https', 'Medium', 'Site is not served over HTTPS',
                        f'{parsed.hostname} is monitored over plain HTTP, so traffic can be read or altered in transit.',
                        'Install a free certificate (for example Let\'s Encrypt) and redirect all HTTP traffic to HTTPS.',
                        f'Monitored URL uses the http:// scheme: {url}')]
    host, port = parsed.hostname, parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [finding('tls', 'invalid-cert', 'Critical', 'SSL certificate is invalid',
                        f'Browsers will show a security warning for {host}: {e.verify_message}.',
                        'Renew or replace the certificate so it is valid, trusted and matches the domain name.',
                        f'TLS handshake with {host}:{port} failed certificate verification: {e.verify_message}')]
    except (OSError, ssl.SSLError):
        return []
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    if days < 0:
        severity, key = 'Critical', 'expired'
    elif days <= 14:
        severity, key = 'High', 'expires-14d'
    elif days <= 30:
        severity, key = 'Medium', 'expires-30d'
    else:
        return []
    return [finding('tls', key, severity, f'SSL certificate expires in {days} days' if days >= 0 else 'SSL certificate has expired',
                    f'The certificate for {host} expires on {expires:%Y-%m-%d}.',
                    'Renew the certificate now, and enable automatic renewal so it does not lapse again.',
                    f'Certificate presented by {host}:{port} has notAfter = {cert["notAfter"]}')]

def check_https_redirect(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return []
    plain = parsed._replace(scheme='http', netloc=parsed.hostname).geturl()
    try:
        response = requests.get(plain, timeout=TIMEOUT, allow_redirects=False,
                                headers={'User-Agent': config.USER_AGENT})
    except requests.RequestException:
        return []
    location = response.headers.get('Location', '')
    if response.is_redirect and location.startswith('https://'):
        return []
    if response.status_code < 400:
        return [finding('https-redirect', 'no-redirect', 'Medium', 'HTTP version of the site does not redirect to HTTPS',
                        f'{plain} answers with status {response.status_code} instead of redirecting to HTTPS.',
                        'Configure the web server to send a permanent (301) redirect from HTTP to HTTPS.',
                        f'GET {plain} returned HTTP {response.status_code} with no redirect to https://')]
    return []

SECURITY_HEADERS = [
    ('Strict-Transport-Security', 'Medium', True,
     'Browsers are not told to always use HTTPS, which allows downgrade attacks.',
     'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".'),
    ('Content-Security-Policy', 'Medium', False,
     'No Content Security Policy limits which scripts can run, so any XSS bug is easier to exploit.',
     'Add a Content-Security-Policy header, starting with "default-src \'self\'" and loosening only what the site needs.'),
    ('X-Frame-Options', 'Low', False,
     'The site can be embedded in other sites\' frames, which enables clickjacking.',
     'Add "X-Frame-Options: DENY" (or a CSP frame-ancestors directive).'),
    ('X-Content-Type-Options', 'Low', False,
     'Browsers may guess content types, which can turn uploaded files into scripts.',
     'Add "X-Content-Type-Options: nosniff".'),
    ('Referrer-Policy', 'Low', False,
     'Full page URLs, which can contain private data, leak to other sites through the Referer header.',
     'Add "Referrer-Policy: strict-origin-when-cross-origin".'),
]

def check_headers(url, response):
    results = []
    is_https = urlparse(response.url or url).scheme == 'https'
    csp = response.headers.get('Content-Security-Policy', '')
    for name, severity, https_only, detail, fix in SECURITY_HEADERS:
        if https_only and not is_https:
            continue
        if name in response.headers:
            continue
        if name == 'X-Frame-Options' and 'frame-ancestors' in csp:
            continue
        results.append(finding('headers', name.lower(), severity, f'Missing {name} header', detail, fix,
                               f'{_observed(response)} without a {name} header'))
    return results

def check_cookies(url, response):
    results = []
    is_https = urlparse(response.url or url).scheme == 'https'
    for cookie in response.raw.headers.getlist('Set-Cookie') if response.raw is not None else []:
        name = cookie.split('=', 1)[0].strip()
        flags = cookie.lower()
        missing = []
        if is_https and 'secure' not in flags:
            missing.append('Secure')
        if 'httponly' not in flags:
            missing.append('HttpOnly')
        if missing:
            results.append(finding('cookies', name, 'Low', f'Cookie "{name}" is missing {" and ".join(missing)}',
                                   f'The "{name}" cookie is set without the {", ".join(missing)} flag(s), '
                                   'so it can be stolen by scripts or sent over unencrypted connections.',
                                   'Set cookies with the Secure, HttpOnly and SameSite attributes.',
                                   f'{_observed(response)}; Set-Cookie for "{name}" lacks {", ".join(missing)}'))
    return results

def check_version_disclosure(url, response):
    results = []
    server = response.headers.get('Server', '')
    if re.search(r'\d', server):
        results.append(finding('disclosure', 'server', 'Low', 'Server header reveals software version',
                               f'The server identifies itself as "{server}", which helps attackers pick known exploits.',
                               'Hide the version in the web server config (for example "server_tokens off" in nginx).',
                               f'{_observed(response)} with header Server: {server}'))
    powered = response.headers.get('X-Powered-By')
    if powered:
        results.append(finding('disclosure', 'x-powered-by', 'Low', 'X-Powered-By header reveals technology',
                               f'The site sends "X-Powered-By: {powered}".',
                               'Remove the X-Powered-By header in the application or web server config.',
                               f'{_observed(response)} with header X-Powered-By: {powered}'))
    return results

def _looks_like_env(body):
    text = body.decode('utf-8', 'ignore')
    return '<html' not in text.lower() and re.search(r'^[A-Z][A-Z0-9_]*=', text, re.M) is not None

# (path, severity, title, matcher) - a matcher on the body avoids alerting on "soft 404" pages
EXPOSED_FILES = [
    ('/.git/HEAD', 'Critical', 'Git repository is publicly downloadable',
     lambda b: b.startswith(b'ref:') or re.fullmatch(rb'[0-9a-f]{40}\s*', b) is not None),
    ('/.git/config', 'Critical', 'Git repository is publicly downloadable', lambda b: b'[core]' in b),
    ('/.env', 'Critical', 'Environment file with secrets is public', _looks_like_env),
    ('/wp-config.php.bak', 'Critical', 'WordPress config backup is public', lambda b: b'DB_PASSWORD' in b),
    ('/backup.sql', 'High', 'Database backup is public', lambda b: b'CREATE TABLE' in b or b'INSERT INTO' in b),
    ('/backup.zip', 'High', 'Backup archive is public', lambda b: b.startswith(b'PK\x03\x04')),
    ('/phpinfo.php', 'Medium', 'phpinfo() page is public', lambda b: b'PHP Version' in b),
    ('/.DS_Store', 'Low', '.DS_Store file lists directory contents', lambda b: b[4:8] == b'Bud1'),
]

def check_exposed_files(url):
    results = []
    reported = set()
    for path, severity, title, matches in EXPOSED_FILES:
        if title in reported:
            continue
        target = urljoin(url, path)
        try:
            response = requests.get(target, timeout=TIMEOUT, allow_redirects=False, stream=True,
                                    headers={'User-Agent': config.USER_AGENT})
            body = response.raw.read(MAX_BODY, decode_content=True) if response.status_code == 200 else b''
            response.close()
        except requests.RequestException:
            continue
        if body and matches(body):
            reported.add(title)
            # Never include the file contents: alerts must not spread the secrets
            results.append(finding('exposed-files', path, severity, title,
                                   f'{target} is readable by anyone on the internet.',
                                   f'Block access to {path} in the web server config, delete it from the web root, '
                                   'and rotate any passwords or keys it contained.',
                                   f'GET {target} returned HTTP 200 with {len(body)} bytes matching the file format '
                                   '(contents not stored)'))
    return results

def check_injection(url, response):
    results = []
    if not any(marker in response.text for marker in ('SQL syntax', 'mysql_fetch', 'ORA-')):
        if sql_injection.test_sql_injection(url)['vulnerabilities']:
            results.append(finding('sqli', 'id-param', 'High', 'Possible SQL injection',
                                   'Adding a quote to the "id" parameter makes the page return a database error.',
                                   'Use parameterised queries (prepared statements) for every database query.',
                                   f'GET {url} with id=\' returned a page containing a database error message'))
    if xss.test_xss(url)['vulnerabilities']:
        results.append(finding('xss', 'q-param', 'High', 'Reflected cross-site scripting (XSS)',
                               'A script passed in the "q" parameter is echoed back into the page without escaping.',
                               'Escape all user input when rendering HTML, and add a Content-Security-Policy.',
                               f'GET {url} with q=<script>alert(\'XSS\')</script> returned the script unescaped'))
    return results

def run_all(url, active=False):
    """Run every check. Returns (findings, error); error is set when the site could not be reached.

    Active tests (SQL injection and XSS probes) only run when the client's written
    authorisation explicitly covers them.
    """
    if (error := validate_target(url)):
        return [], error
    findings = check_tls(url) + check_https_redirect(url)
    try:
        response = safe_get(url)
    except requests.RequestException as e:
        return findings, f'Could not reach {url}: {e}'
    findings += check_headers(url, response)
    findings += check_cookies(url, response)
    findings += check_version_disclosure(url, response)
    findings += check_exposed_files(response.url or url)
    if active:
        findings += check_injection(response.url or url, response)
    return findings, None
