import requests

def test_xss(target_url):
    vulnerabilities = []
    payload = "<script>alert('XSS')</script>"
    params = {'q': payload}
    try:
        response = requests.get(target_url, params=params, timeout=5)
        if payload in response.text:
            vulnerabilities.append({
                'payload': payload,
                'evidence': 'XSS payload was reflected in the response.'
            })
    except Exception as e:
        vulnerabilities.append({
            'payload': payload,
            'error': str(e)
        })
    return vulnerabilities if vulnerabilities else "No Cross-Site Scripting vulnerability detected."
