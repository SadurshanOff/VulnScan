import ipaddress
import os
import socket
from urllib.parse import urlparse

# Set VULNSCAN_ALLOW_PRIVATE=1 to scan local lab targets (e.g. DVWA on localhost)
ALLOW_PRIVATE = os.environ.get('VULNSCAN_ALLOW_PRIVATE') == '1'

def validate_target(target_url):
    """Return an error message if the URL should not be scanned, else None."""
    parsed = urlparse(target_url)
    if parsed.scheme not in ('http', 'https'):
        return 'URL must start with http:// or https://'
    if not parsed.hostname:
        return 'URL must include a host name'
    if ALLOW_PRIVATE:
        return None
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        return f'Could not resolve host {parsed.hostname}'
    for address in addresses:
        if not ipaddress.ip_address(address.split('%')[0]).is_global:
            return (f'{parsed.hostname} resolves to a private or internal address. '
                    'Set VULNSCAN_ALLOW_PRIVATE=1 to scan local lab targets.')
    return None
