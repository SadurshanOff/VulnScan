import os

DB_PATH = os.environ.get('VULNSCAN_DB', 'vulnscan.db')
SCAN_INTERVAL_HOURS = int(os.environ.get('VULNSCAN_SCAN_INTERVAL_HOURS', '6'))
DIGEST_INTERVAL_DAYS = int(os.environ.get('VULNSCAN_DIGEST_INTERVAL_DAYS', '7'))
ADMIN_PASSWORD = os.environ.get('VULNSCAN_ADMIN_PASSWORD')
CONTACT_URL = os.environ.get('VULNSCAN_CONTACT_URL', 'https://github.com/SadurshanOff/VulnScan')
USER_AGENT = f'VulnScanMonitor/1.0 (+{CONTACT_URL})'

SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER or 'vulnscan@localhost')
SMTP_STARTTLS = os.environ.get('SMTP_STARTTLS', '1') == '1'

TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')

# When on, new findings wait for analyst approval before the client is alerted
REVIEW_REQUIRED = os.environ.get('VULNSCAN_REVIEW_REQUIRED', '1') == '1'
# Where review requests go (the analyst running the service)
ADMIN_EMAIL = os.environ.get('VULNSCAN_ADMIN_EMAIL')
ADMIN_TELEGRAM_CHAT_ID = os.environ.get('VULNSCAN_ADMIN_TELEGRAM_CHAT_ID')
