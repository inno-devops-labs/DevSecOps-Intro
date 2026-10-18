#!/usr/bin/env python3
"""Rotate the local lab certificate during 100 fresh HTTPS requests."""
import collections
import concurrent.futures
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / 'labs/lab11'
CERTS = LAB / 'reverse-proxy/certs'
CTX = ssl._create_unverified_context()
CMD = ['docker', 'compose', '-f', str(LAB / 'docker-compose.yml'), 'exec', '-T', 'nginx']


def serial(pem):
    return subprocess.check_output(['openssl', 'x509', '-noout', '-serial'], input=pem).decode().strip()


def live_serial():
    return serial(ssl.get_server_certificate(('localhost', 443)).encode())


old = live_serial()
subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '30',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                '-keyout', str(CERTS / 'next.key'), '-out', str(CERTS / 'next.crt')],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for suffix in ('crt', 'key'):
    shutil.copy2(CERTS / f'localhost.{suffix}', CERTS / f'previous.{suffix}')
    (CERTS / f'next.{suffix}').chmod(0o644)
new = serial((CERTS / 'next.crt').read_bytes())


def traffic():
    codes = []
    for _ in range(100):
        try:
            with urllib.request.urlopen('https://localhost/rest/admin/application-version', context=CTX, timeout=10) as r:
                codes.append(r.status)
        except Exception as exc:
            codes.append(type(exc).__name__)
        time.sleep(0.05)
    return codes


with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    pending = pool.submit(traffic)
    time.sleep(1)
    # Workers keep the old pair in memory; do not reload until BOTH files are installed.
    for suffix in ('crt', 'key'):
        (CERTS / f'next.{suffix}').replace(CERTS / f'localhost.{suffix}')
    try:
        subprocess.run(CMD + ['nginx', '-t'], check=True)
        subprocess.run(CMD + ['nginx', '-s', 'reload'], check=True)
    except Exception:
        for suffix in ('crt', 'key'):
            shutil.copy2(CERTS / f'previous.{suffix}', CERTS / f'localhost.{suffix}')
        raise
    time.sleep(0.5)
    actual = live_serial()
    codes = pending.result()
result = {'old_serial': old, 'new_serial_on_disk': new, 'live_serial_after_reload': actual,
          'requests': len(codes), 'status_counts': dict(collections.Counter(map(str, codes)))}
(LAB / 'results/rotation.json').write_text(json.dumps(result, indent=2) + '\n')
assert old != new and actual == new and codes == [200] * 100, result
print(json.dumps(result, indent=2))
