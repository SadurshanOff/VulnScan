import logging
import smtplib
from email.message import EmailMessage

import requests

from monitor import config

log = logging.getLogger(__name__)

SEVERITY_ICON = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵'}

def _describe(row):
    return f"{SEVERITY_ICON.get(row['severity'], '')} [{row['severity']}] {row['title']}\n   {row['detail']}\n   Fix: {row['fix']}"

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
