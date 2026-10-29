import logging
import smtplib
from email.message import EmailMessage

import requests

from monitor import config

log = logging.getLogger(__name__)

SEVERITY_ICON = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵'}

def _describe(row):
    lines = [f"{SEVERITY_ICON.get(row['severity'], '')} [{row['severity']}] {row['title']}", f"   {row['detail']}"]
    if row['analyst_note']:
        lines.append(f"   Analyst note: {row['analyst_note']}")
    lines.append(f"   Fix: {row['fix']}")
    if row['evidence']:
        lines.append(f"   Evidence: {row['evidence']}")
    return '\n'.join(lines)

def format_changes(site, opened, resolved):
    subject = f"[VulnScan] {site['name']}: {len(opened)} new, {len(resolved)} fixed"
    lines = [f"Security update for {site['name']} ({site['url']})", '']
    if opened:
        lines.append(f'New issues found ({len(opened)}):')
        lines += [_describe(row) for row in opened]
        lines.append('')
    if resolved:
        lines.append(f'Fixed since the last scan ({len(resolved)}):')
        lines += [f"✅ {row['title']}" for row in resolved]
        lines.append('')
    lines.append('VulnScan Monitor keeps checking your site around the clock.')
    return subject, '\n'.join(lines)

def format_digest(site, open_rows):
    subject = f"[VulnScan] Weekly summary for {site['name']}"
    if open_rows:
        body = [f"{site['name']} ({site['url']}) still has {len(open_rows)} open issue(s):", '']
        body += [_describe(row) for row in open_rows]
    else:
        body = [f"All clear: no open issues on {site['name']} ({site['url']}). Monitoring is active."]
    return subject, '\n'.join(body)

def format_review_request(site, opened):
    subject = f"[VulnScan] Review needed: {len(opened)} new finding(s) on {site['name']}"
    lines = [f"New findings on {site['name']} ({site['url']}) are waiting for your review.",
             'The client has not been told yet.', '']
    lines += [_describe(row) for row in opened]
    return subject, '\n'.join(lines)

def format_unverified(site):
    subject = f"[VulnScan] Monitoring paused for {site['name']}"
    body = (f"We could no longer find the verification file on {site['url']}, so monitoring is paused.\n"
            'Put the verification file back in place, then ask your provider to re-verify the site.')
    return subject, body

def send_email(to, subject, text):
    if not config.SMTP_HOST or not to:
        return False
    message = EmailMessage()
    message['From'] = config.SMTP_FROM
    message['To'] = to
    message['Subject'] = subject
    message.set_content(text)
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as smtp:
        if config.SMTP_STARTTLS:
            smtp.starttls()
        if config.SMTP_USER:
            smtp.login(config.SMTP_USER, config.SMTP_PASSWORD or '')
        smtp.send_message(message)
    return True

def send_telegram(chat_id, text):
    if not config.TELEGRAM_BOT_TOKEN or not chat_id:
        return False
    response = requests.post(f'https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage',
                             json={'chat_id': chat_id, 'text': text[:4000], 'disable_web_page_preview': True},
                             timeout=20)
    response.raise_for_status()
    return True

def notify_admin(subject, text):
    """Message the analyst running the service. Returns the channels that succeeded."""
    return notify({'id': 'admin', 'owner_email': config.ADMIN_EMAIL,
                   'telegram_chat_id': config.ADMIN_TELEGRAM_CHAT_ID}, subject, text)

def notify(site, subject, text):
    """Send to every channel the site has. Returns the channels that succeeded."""
    sent = []
    for channel, send in (('email', lambda: send_email(site['owner_email'], subject, text)),
                          ('telegram', lambda: send_telegram(site['telegram_chat_id'], f'{subject}\n\n{text}'))):
        try:
            if send():
                sent.append(channel)
        except Exception:
            log.exception('Sending %s alert for site %s failed', channel, site['id'])
    return sent

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Send a test alert to check email and Telegram settings')
    parser.add_argument('--email', help='address to send a test email to')
    parser.add_argument('--telegram', help='Telegram chat id to send a test message to')
    args = parser.parse_args()
    if not args.email and not args.telegram:
        parser.error('give --email and/or --telegram')
    logging.basicConfig(level=logging.INFO)

    subject = '[VulnScan] Test alert'
    text = 'This is a test message from VulnScan Monitor. If you can read it, alerts are set up correctly.'
    ok = True
    for channel, target, send, missing in (
            ('email', args.email, lambda: send_email(args.email, subject, text), 'SMTP_HOST is not set'),
            ('telegram', args.telegram, lambda: send_telegram(args.telegram, f'{subject}\n\n{text}'),
             'TELEGRAM_BOT_TOKEN is not set')):
        if not target:
            continue
        try:
            sent = send()
        except Exception as e:
            sent, missing = False, f'{type(e).__name__}: {e}'
        print(f'{channel}: {"sent to " + target if sent else "FAILED (" + missing + ")"}')
        ok = ok and sent
    raise SystemExit(0 if ok else 1)

if __name__ == '__main__':
    main()
