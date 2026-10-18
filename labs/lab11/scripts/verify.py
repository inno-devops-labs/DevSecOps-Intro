#!/usr/bin/env python3
"""Run after compose up; captures evidence and fails if an edge control regresses."""
import json
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
OUT = LAB / 'results'
OUT.mkdir(exist_ok=True)
CTX = ssl._create_unverified_context()  # Local self-signed lab certificate only.
COMPOSE = ['docker', 'compose', '-f', str(LAB / 'docker-compose.yml'),
           '-f', str(LAB / 'waf/docker-compose.override.yml')]


def run(name, args, stdin=None, check=True):
    p = subprocess.run(args, input=stdin, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    (OUT / name).write_text(p.stdout)
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.stdout}')
    return p


def request(base, path, data=None):
    try:
        with urllib.request.urlopen(base + path, data=data, context=CTX, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    run('nginx-validation.txt', COMPOSE + ['exec', '-T', 'nginx', 'nginx', '-t'])
    redirect = run('http-redirect.txt', ['curl', '-fsSI', 'http://localhost/a?b=c']).stdout
    assert '308 Permanent Redirect' in redirect and 'https://localhost/a?b=c' in redirect
    headers = run('headers.txt', ['curl', '-fskI', 'https://localhost']).stdout.lower()
    required = ['strict-transport-security', 'x-content-type-options', 'x-frame-options',
                'referrer-policy', 'permissions-policy', 'content-security-policy-report-only']
    assert all('\n' + h + ':' in headers for h in required)
    tls = run('tls13.txt', ['openssl', 's_client', '-connect', 'localhost:443',
                          '-servername', 'localhost', '-tls1_3', '-brief'], '').stdout
    assert 'TLSv1.3' in tls and 'TLS_AES_' in tls
    rejected = run('rejected-suite.txt', ['openssl', 's_client', '-connect', 'localhost:443',
        '-servername', 'localhost', '-tls1_3', '-ciphersuites',
        'TLS_CHACHA20_POLY1305_SHA256'], '', check=False)
    assert rejected.returncode != 0 and 'alert handshake failure' in rejected.stdout
    # Drain all six slots so repeated runs have the same starting conditions.
    time.sleep(36)
    codes = [int(run(f'login-{i}.txt', ['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
        '-X', 'POST', 'https://localhost/rest/user/login', '-H', 'Content-Type: application/json',
        '-d', '{"email":"a@b.c","password":"x"}']).stdout) for i in range(14)]
    (OUT / 'rate-limit.txt').write_text(' '.join(map(str, codes)) + '\n')
    assert codes[:6] == [401]*6 and codes[6:] == [429]*8
    # Non-login traffic must remain available while the login zone is exhausted.
    assert request('https://localhost', '/rest/admin/application-version') == 200
    err = run('error-headers.txt', ['curl', '-skI', '-X', 'POST',
        'https://localhost/rest/user/login']).stdout.lower()
    assert '429' in err and all('\n' + h + ':' in err for h in required)
    rows = []
    for q in ["' OR 1=1--", 'apple', 'orange juice', "O'Reilly", '1 < 2',
              'select a gift', 'union of fruits', '<script>alert(1)</script>']:
        path = '/rest/products/search?' + urllib.parse.urlencode({'q': q})
        rows.append({'query': q, 'plain': request('https://localhost', path),
                     'waf': request('http://localhost:8081', path)})
    (OUT / 'waf-requests.json').write_text(json.dumps(rows, indent=2) + '\n')
    assert rows[0]['plain'] != 403 and rows[0]['waf'] == 403
    start = time.monotonic()
    with socket.create_connection(('localhost', 443), timeout=20) as raw:
        with CTX.wrap_socket(raw, server_hostname='localhost') as s:
            s.sendall(b'POST /rest/products/search HTTP/1.1\r\nHost: localhost\r\n'
                      b'Content-Type: application/json\r\nContent-Length: 100\r\n'
                      b'Connection: close\r\n\r\n{')
            response = b''
            while chunk := s.recv(65536):
                response += chunk
    elapsed = time.monotonic() - start
    (OUT / 'body-timeout.txt').write_text(f'Sent 1 of 100 body bytes; closed after {elapsed:.3f}s\n'
                                         + response.decode(errors='replace'))
    # Nginx may close a partial-body connection without transmitting a response.
    log = (LAB / 'logs/access.log').read_text().splitlines()[-1]
    assert 9 <= elapsed <= 15 and '"POST /rest/products/search HTTP/1.1" 408 ' in log
    (OUT / 'body-timeout.txt').open('a').write(log + '\n')
    run('waf.log', COMPOSE + ['logs', '--no-color', 'waf'])
    assert '942100' in (OUT / 'waf.log').read_text()
    # Probe the internal nginx address, avoiding Docker Desktop host-network assumptions.
    run('protocols.txt', ['docker', 'run', '--rm', '--network', 'lab11_default',
        'drwetter/testssl.sh:3.2', '--protocols', '--color', '0', 'https://nginx:443'])
    protocols = (OUT / 'protocols.txt').read_text()
    assert 'TLS 1      not offered' in protocols and 'TLS 1.1    not offered' in protocols
    assert 'TLS 1.2    offered' in protocols and 'TLS 1.3    offered' in protocols
    print('PASS: redirect, TLS protocols/suites, headers including 429, login-only limit, WAF, timeout')


if __name__ == '__main__':
    main()
