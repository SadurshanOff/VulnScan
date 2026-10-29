# VulnScan Monitor

VulnScan Monitor watches websites around the clock for common security problems and alerts the site owner by email or Telegram when something new appears, and again when it is fixed. It is built for small businesses that have no security team.

> **Important:**
> **Only monitor sites you own or have written permission to test.** VulnScan refuses to scan a site until its owner proves control of it by publishing a verification file.

## What it checks

All checks are low-impact (about 15 ordinary requests per scan) and never modify data.

| Check | Catches |
| --- | --- |
| TLS certificate | Invalid, expired, or expiring within 14 / 30 days |
| HTTPS | Site on plain HTTP, or HTTP not redirecting to HTTPS |
| Security headers | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Cookies | Missing Secure / HttpOnly flags |
| Version disclosure | `Server` or `X-Powered-By` revealing software versions |
| Exposed files | Public `.git`, `.env`, config backups, database dumps, `phpinfo.php`, `.DS_Store` |
| SQL injection | Database errors returned when a quote is added to the `id` parameter |
| Reflected XSS | A script in the `q` parameter echoed back unescaped |

Each finding is alerted once. When a later scan no longer sees it, the owner gets a "fixed" message. A weekly summary confirms monitoring is alive.

## How it works

- **Dashboard** (`app.py`): password-protected pages to add client sites, verify ownership, scan on demand and review findings. The original one-off scanner is still at `/`.
- **Worker** (`monitor/worker.py`): wakes every minute and scans each verified site when it is due (every 6 hours by default). It re-checks the verification file before every scan and pauses monitoring if it has been removed.
- **Checks** (`monitor/checks.py`), **storage** (`monitor/db.py`, SQLite), **alerts** (`monitor/notify.py`, SMTP and the Telegram Bot API).

## Running it

### With Docker (recommended for production)

```bash
cp .env.example .env    # then edit .env
docker compose up -d --build
```

The dashboard listens on `127.0.0.1:8000`. Add `--profile https` to also start Caddy, which serves it on `VULNSCAN_DOMAIN` with an automatic HTTPS certificate. See the full [deployment guide](docs/DEPLOY.md) for a step-by-step production setup.

To check your email and Telegram settings, send a test alert:

```bash
python -m monitor.notify --email you@example.com --telegram 123456789
```

### Locally

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export VULNSCAN_ADMIN_PASSWORD=change-me
python app.py                 # dashboard on http://127.0.0.1:5000
python -m monitor.worker      # in a second terminal: the 24/7 agent
```

`python -m monitor.worker --once` runs a single pass, which is useful from cron.

### Configuration

All settings are environment variables; see [`.env.example`](.env.example).

| Variable | Purpose |
| --- | --- |
| `VULNSCAN_ADMIN_PASSWORD` | Dashboard password (required) |
| `VULNSCAN_SECRET_KEY` | Flask secret key; random per start if unset |
| `VULNSCAN_DB` | SQLite path (default `vulnscan.db`) |
| `VULNSCAN_SCAN_INTERVAL_HOURS` | Hours between scans of a site (default 6) |
| `VULNSCAN_DIGEST_INTERVAL_DAYS` | Days between summary messages (default 7) |
| `VULNSCAN_CONTACT_URL` | Shown in the scanner's User-Agent so site hosts know who is scanning |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | Email alerts |
| `TELEGRAM_BOT_TOKEN` | Telegram alerts (create a bot with @BotFather) |
| `VULNSCAN_ALLOW_PRIVATE=1` | Allow localhost / private network targets, for lab testing only |
| `FLASK_DEBUG=1` | Debug mode; never on a reachable host |

## Onboarding a client

1. Get the client's written permission to monitor their site.
2. In the dashboard, open **Monitored sites** and add the site with the owner's email and/or Telegram chat id. To find a chat id, the owner messages your bot and you open `https://api.telegram.org/bot<token>/getUpdates`.
3. Send the owner the verification token shown on the site page. They publish it as the only content of `https://their-site/.well-known/vulnscan-verify.txt`.
4. Click **Verify**. The worker starts scanning on its next pass, and the owner gets their first report.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

The tests start local HTTP servers, so they need no network access.

## Disclaimer

Provided for authorised security monitoring only. The developer assumes no responsibility for misuse. Always have written permission before scanning a site.
