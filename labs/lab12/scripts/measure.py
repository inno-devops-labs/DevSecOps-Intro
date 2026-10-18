#!/usr/bin/env python3
"""Collect Lab 12 evidence on the disposable Linux/KVM host, as root."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=Path('results'))
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
IMAGE = 'alpine:3.20'
BASE = ['nerdctl', '--namespace', 'lab12']
result = {'date_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'host_kernel': platform.release(), 'architecture': platform.machine(),
          'image': IMAGE, 'commands': [], 'runtimes': {}}


def save():
    (args.output / 'measurements.json').write_text(json.dumps(result, indent=2) + '\n')


def command(argv, *, check=True):
    begin = time.perf_counter()
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=180)
    duration = time.perf_counter() - begin
    record = {'argv': argv, 'exit_code': proc.returncode,
              'stdout': proc.stdout, 'stderr': proc.stderr, 'elapsed_seconds': duration}
    result['commands'].append(record)
    save()
    if check and proc.returncode:
        raise RuntimeError(record)
    return record


def run(runtime, *args):
    flag = [] if runtime == 'runc' else ['--runtime=io.containerd.kata.v2']
    return command(BASE + ['run', '--rm'] + flag + [IMAGE, *args])


assert os.geteuid() == 0 and platform.system() == 'Linux'
assert Path('/dev/kvm').is_char_device()
for cmd in [['uname', '-a'], ['containerd', '--version'], ['nerdctl', 'version'],
            ['cat', '/opt/kata/VERSION'], ['/opt/kata/bin/kata-runtime', '--version']]:
    command(cmd)
command(BASE + ['pull', IMAGE])
command(BASE + ['image', 'inspect', IMAGE])

for runtime in ('runc', 'kata'):
    print('Measuring', runtime, flush=True)
    data = result['runtimes'][runtime] = {}
    data['kernel'] = run(runtime, 'uname', '-r')['stdout'].strip()
    device_list = run(runtime, 'ls', '-1', '/dev')['stdout'].splitlines()
    data['devices'] = device_list
    data['device_count'] = len(device_list)
    data['cap_eff'] = run(runtime, 'sh', '-c', 'grep ^CapEff /proc/1/status')['stdout'].strip()
    # Image pull and a complete warm-up run are outside the timed sample.
    run(runtime, 'true')
    timings = []
    for _ in range(5):
        sample = run(runtime, 'true')
        timings.append(round(sample['elapsed_seconds'], 6))
    data['startup_seconds'] = timings
    data['startup_median_seconds'] = statistics.median(timings)
    data['io'] = run(runtime, 'sh', '-o', 'pipefail', '-c',
                     'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1 | tail -1')['stdout'].strip()
    save()

assert result['runtimes']['runc']['kernel'] == result['host_kernel']
assert result['runtimes']['kata']['kernel'] != result['host_kernel']
print(json.dumps(result['runtimes'], indent=2))
print('PASS: two runtimes, kernel comparison, five warmed startup runs each and fsynced 512 MiB I/O')
