#!/usr/bin/env python3
"""Live lab11 checks; run with the base and WAF Compose files active."""
import http.client
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlencode

OUT = Path(__file__).resolve().parents[1] / 'results'
OUT.mkdir(exist_ok=True)
CTX = ssl._create_unverified_context()  # Local self-signed lab certificate.
HEADERS = ['strict-transport-security', 'x-content-type-options', 'x-frame-options',
           'referrer-policy', 'permissions-policy', 'content-security-policy-report-only']


def request(path='/', *, waf=False, method='GET', body=None, headers=None):
    c = (http.client.HTTPConnection('localhost', 8081, timeout=15) if waf else
         http.client.HTTPSConnection('localhost', 443, context=CTX, timeout=15))
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    result = {'status': r.status, 'headers': dict(r.getheaders()), 'body': r.read().decode(errors='replace')}
    c.close()
    return result


def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + '\n')


c = http.client.HTTPConnection('localhost', 80, timeout=10)
c.request('POST', '/test?x=1', body='example')
r = c.getresponse()
redirect = {'status': r.status, 'location': r.getheader('Location')}
c.close()
assert redirect == {'status': 308, 'location': 'https://localhost/test?x=1'}, redirect
save('redirect.json', redirect)

samples = {}
for name, path, method, body in [
    ('success', '/', 'GET', None),
    ('upstream401', '/rest/user/login', 'POST', '{"email":"a@b.c","password":"x"}'),
    ('proxy413', '/rest/user/login', 'POST', 'x' * (2 * 1024 * 1024 + 1)),
]:
    result = request(path, method=method, body=body, headers={'Content-Type': 'application/json'})
    h = {k.lower(): v for k, v in result['headers'].items()}
    assert all(k in h for k in HEADERS), (name, h)
    assert result['status'] == {'success': 200, 'upstream401': 401, 'proxy413': 413}[name], result['status']
    samples[name] = {'status': result['status'], 'headers': h}
save('headers.json', samples)

# Quiet period drains the 10 requests/minute bucket before the specified burst.
time.sleep(36)
codes = [request('/rest/user/login', method='POST', body='{"email":"a@b.c","password":"x"}',
                 headers={'Content-Type': 'application/json'})['status'] for _ in range(14)]
assert 401 in codes and 429 in codes and set(codes) == {401, 429}, codes
variants = ['/REST/USER/LOGIN', '/rest/user/login/']
assert all(request(p, method='POST', body='{}', headers={'Content-Type': 'application/json'})['status'] == 429 for p in variants)
# Rate limiting must not apply to the rest of the site.
assert all(request('/rest/admin/application-version')['status'] == 200 for _ in range(14))
limited = request('/rest/user/login', method='POST', body='{}', headers={'Content-Type': 'application/json'})
assert limited['status'] == 429
assert all(k in {h.lower() for h in limited['headers']} for k in HEADERS)
save('rate-limit.json', {'rate': '10r/m', 'burst': 5, 'nodelay': True, 'codes': codes,
                         'login_variants': {p: 429 for p in variants}, 'non_login_14_requests': 'all 200', 'headers_on_429': limited['headers']})

# A complete header followed by an incomplete body counts as an active request.
# Hold 20 such requests, proving the per-address connection cap with the 21st.
held = []
try:
    for _ in range(20):
        s = CTX.wrap_socket(socket.create_connection(('localhost', 443)), server_hostname='localhost')
        s.sendall(b'POST /rest/products/search HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{')
        held.append(s)
    time.sleep(0.4)
    cap = request('/rest/admin/application-version')
    assert cap['status'] == 429, cap['status']
    save('connections.json', {'held_requests': len(held), 'next_request_status': cap['status']})
finally:
    for s in held:
        s.close()

# Trigger client_body_timeout by stopping after the first byte of the body.
s = CTX.wrap_socket(socket.create_connection(('localhost', 443)), server_hostname='localhost')
s.settimeout(20)
start = time.monotonic()
s.sendall(b'POST /rest/products/search HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{')
data = s.recv(65536)
elapsed = time.monotonic() - start
s.close()
# nginx may close the incomplete upload without sending an HTTP response.
# Require the matching 408 access-log entry as well as the measured deadline.
time.sleep(0.2)
last = (OUT.parent / 'logs/access.log').read_text().splitlines()[-1]
assert 9 <= elapsed < 16 and '"POST /rest/products/search HTTP/1.1" 408 ' in last, (data, elapsed, last)
save('timeout.json', {'command': 'python3 labs/lab11/scripts/verify.py', 'elapsed_seconds': round(elapsed, 3),
                      'response': data.decode(errors='replace'), 'access_log': last})

payload = '/rest/products/search?' + urlencode({'q': "' OR 1=1--"})
plain = request(payload)
waf = request(payload, waf=True)
assert plain['status'] == 500 and waf['status'] == 403, (plain['status'], waf['status'])
save('waf-comparison.json', {'path': payload, 'plain_status': plain['status'], 'waf_status': waf['status']})

corpus = []
for path in ['/', '/rest/admin/application-version', '/api/Products', '/rest/user/whoami',
             '/rest/products/search?' + urlencode({'q': 'apple'}),
             '/rest/products/search?' + urlencode({'q': "O'Reilly"}),
             '/rest/products/search?' + urlencode({'q': 'green apple & orange'}),
             '/rest/products/search?' + urlencode({'q': 'яблоко'})]:
    a, b = request(path), request(path, waf=True)
    corpus.append({'path': path, 'plain_status': a['status'], 'waf_status': b['status']})
# Record false positives honestly instead of assuming their absence.
save('false-positive-hunt.json', corpus)
print(json.dumps({'redirect': redirect, 'rate_codes': codes, 'connection_cap': cap['status'],
                  'timeout_seconds': round(elapsed, 3), 'plain_sqli': plain['status'],
                  'waf_sqli': waf['status'], 'benign_requests': corpus}, indent=2))
print('PASS: redirect, headers on 200/401/413/429, login-only rate limit, connection cap, live timeout, WAF comparison')
