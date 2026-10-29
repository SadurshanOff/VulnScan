import requests

def test_sql_injection(target_url):
    vulnerabilities = []
    errors = []
    # Non-destructive probes only: they break query syntax but never modify data
    payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
    for payload in payloads:
        params = {'id': payload}
        try:
            response = requests.get(target_url, params=params, timeout=5, allow_redirects=False)
            if ("SQL syntax" in response.text or
                "mysql_fetch" in response.text or
                "ORA-" in response.text):
                vulnerabilities.append({
                    'payload': payload,
                    'evidence': 'SQL error message found in response.'
                })
        except requests.RequestException as e:
            errors.append({
                'payload': payload,
                'error': str(e)
            })
    return {'vulnerabilities': vulnerabilities, 'errors': errors}
