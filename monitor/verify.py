import secrets
from urllib.parse import urljoin

import requests

from monitor import config

VERIFY_PATH = '/.well-known/vulnscan-verify.txt'

def new_token():
    return secrets.token_urlsafe(24)

def verification_url(site_url):
    return urljoin(site_url, VERIFY_PATH)

def check_ownership(site_url, token):
    """True if the site publishes its verification token, proving the client controls it."""
    try:
        response = requests.get(verification_url(site_url), timeout=10, allow_redirects=False,
                                headers={'User-Agent': config.USER_AGENT})
    except requests.RequestException:
        return False
    return response.status_code == 200 and response.text.strip() == token
