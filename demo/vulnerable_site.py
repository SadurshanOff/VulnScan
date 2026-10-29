"""A deliberately weak website for sales demos and testing. Never expose it to the internet.

    python -m demo.vulnerable_site --port 8080 --token <verification token>

Then run the dashboard with VULNSCAN_ALLOW_PRIVATE=1 and add http://127.0.0.1:8080/
as a site. Every check finds something, so a demo shows the full review, report
and retest flow.
"""
import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FAKE_ENV = b'APP_ENV=production\nDB_PASSWORD=demo-not-a-real-password\nSTRIPE_KEY=sk_demo_123\n'

def make_handler(token, fixed):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'Apache/2.4.29'
        sys_version = ''

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == '/.well-known/vulnscan-verify.txt':
                return self.reply(200, token.encode() if token else b'', 'text/plain')
            if parsed.path == '/.env' and not fixed:
                return self.reply(200, FAKE_ENV, 'text/plain')
            if parsed.path != '/':
                return self.reply(404, b'<html>Not found</html>')

            body = '<html><head><title>Demo Bakery</title></head><body><h1>Demo Bakery</h1>'
            if "'" in query.get('id', [''])[0] and not fixed:
                body += '<p>You have an error in your SQL syntax near \'\'\' at line 1</p>'
            if 'q' in query:
                term = query['q'][0]
                body += f'<p>Results for {html.escape(term) if fixed else term}</p>'
            body += '</body></html>'
            self.reply(200, body.encode())

        def reply(self, status, body, content_type='text/html'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            if fixed:
                self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
                self.send_header('Set-Cookie', 'session=demo; HttpOnly; SameSite=Lax')
            else:
                self.send_header('X-Powered-By', 'PHP/7.2.1')
                self.send_header('Set-Cookie', 'session=demo; Path=/')
            self.end_headers()
            self.wfile.write(body)

        def version_string(self):
            return 'nginx' if fixed else self.server_version

        def log_message(self, *args):
            pass

    return Handler

def main():
    parser = argparse.ArgumentParser(description='Deliberately vulnerable demo site')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--token', default='', help='verification token shown on the site page in the dashboard')
    parser.add_argument('--fixed', action='store_true', help='serve the hardened version to demo a retest')
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(args.token, args.fixed))
    print(f'Demo site ({"fixed" if args.fixed else "vulnerable"}) on http://127.0.0.1:{args.port}/ - Ctrl+C to stop')
    server.serve_forever()

if __name__ == '__main__':
    main()
