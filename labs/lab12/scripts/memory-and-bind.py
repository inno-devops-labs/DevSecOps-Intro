#!/usr/bin/env python3
"""Measure idle runtime PSS and run the specified privileged bind-mount test."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=Path('results'))
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
BASE = ['nerdctl', '--namespace', 'lab12']
IMAGE = 'alpine:3.20'
result = {'memory_method': 'PSS sum of new long-lived workload processes versus pre-start PID set; three samples, median',
          'memory': {}, 'bonus': {}, 'commands': []}


def save():
    (args.output / 'memory-and-bind.json').write_text(json.dumps(result, indent=2) + '\n')


def command(argv):
    p = subprocess.run(argv, text=True, capture_output=True, timeout=180)
    result['commands'].append({'argv': argv, 'exit_code': p.returncode,
                               'stdout': p.stdout, 'stderr': p.stderr})
    save()
    if p.returncode:
        raise RuntimeError(result['commands'][-1])
    return p.stdout.strip()


def pids():
    return {int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit()}


def sample(new_pids):
    processes = []
    for pid in sorted(new_pids):
        try:
            proc = Path('/proc') / str(pid)
            fields = dict(line.split(':', 1) for line in (proc / 'smaps_rollup').read_text().splitlines() if ':' in line)
            pss = int(fields['Pss'].split()[0])
            processes.append({'pid': pid, 'command': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode().strip(),
                              'pss_kib': pss})
        except (OSError, KeyError, ValueError):
            continue
    return {'processes': processes, 'total_pss_kib': sum(p['pss_kib'] for p in processes)}


assert os.geteuid() == 0 and Path('/dev/kvm').is_char_device()
for runtime in ('runc', 'kata'):
    flag = [] if runtime == 'runc' else ['--runtime=io.containerd.kata.v2']
    name = 'lab12-memory-' + runtime
    before = pids()
    command(BASE + ['run', '-d', '--name', name] + flag + [IMAGE, 'sleep', '300'])
    try:
        time.sleep(5)
        new = pids() - before
        samples = []
        for _ in range(3):
            samples.append(sample(new))
            time.sleep(1)
        assert all(s['total_pss_kib'] > 0 for s in samples), samples
        result['memory'][runtime] = {'samples': samples,
                                     'median_pss_kib': statistics.median(s['total_pss_kib'] for s in samples)}
    finally:
        command(BASE + ['rm', '-f', name])
    save()

# Sentinel lives only in the disposable Linux VM, not in a macOS bind mount.
target = Path('/tmp/lab12-target')
if target.exists():
    raise RuntimeError('Refusing to overwrite pre-existing /tmp/lab12-target; remove the previous lab sentinel first')
try:
    for runtime in ('runc', 'kata'):
        flag = [] if runtime == 'runc' else ['--runtime=io.containerd.kata.v2']
        prefix = BASE + ['run', '--rm'] + flag + ['--privileged']
        target.write_text('original\n')
        output = command(prefix + ['-v', '/tmp:/host_tmp', IMAGE, 'sh', '-c',
                                   'echo "OVERWRITTEN" > /host_tmp/lab12-target'])
        rec = result['commands'][-1]
        data = {'before': 'original', 'stdout': output, 'exit_code': rec['exit_code'],
                'stderr': rec['stderr'], 'host_file_after': target.read_text().strip()}
        assert data['host_file_after'] == 'OVERWRITTEN', data
        probe = command(prefix + [IMAGE, 'sh', '-c',
                        'ls /dev | wc -l; grep ^CapEff /proc/1/status'])
        rec = result['commands'][-1]
        data['privileged_probe'] = {'exit_code': rec['exit_code'], 'stdout': probe, 'stderr': rec['stderr']}
        lines = probe.splitlines()
        data['device_count'] = int(lines[0])
        data['cap_eff'] = lines[1]
        assert data['device_count'] > 15, data
        assert int(lines[1].split()[1], 16) == 0x1ffffffffff, data
        result['bonus'][runtime] = data
        save()
finally:
    target.unlink(missing_ok=True)
assert all(c['exit_code'] == 0 for c in result['commands'])
print(json.dumps({k: v for k, v in result.items() if k != 'commands'}, indent=2))
print('PASS: memory sampled; exact privileged commands, host writes, device counts and full capability masks verified for both runtimes')
