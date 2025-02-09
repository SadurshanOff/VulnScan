import requests
from scanner import sql_injection, xss

def start_scan(target_url):
    results = {}
    sql_results = sql_injection.test_sql_injection(target_url)
    results['SQL Injection'] = sql_results
    xss_results = xss.test_xss(target_url)
    results['Cross-Site Scripting'] = xss_results
    return results
