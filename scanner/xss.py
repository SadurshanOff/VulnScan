import requests

def test_xss(target_url):
    vulnerabilities = []
    errors = []
    payload = "<script>alert('XSS')</script>"
    params = {'q': payload}
    try:
        response = requests.get(target_url, params=params, timeout=5, allow_redirects=False)
        if payload in response.text:
            vulnerabilities.append({
                'payload': payload,
                'evidence': 'XSS payload was reflected in the response.'
            })
    except requests.RequestException as e:
        errors.append({
            'payload': payload,
            'error': str(e)
        })
    return {'vulnerabilities': vulnerabilities, 'errors': errors}
