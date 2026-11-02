#!/usr/bin/env python3
"""Docker-only partial lab 12 evidence; does not claim to run Kata or nerdctl."""
import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
OUT = LAB / 'results'
OUT.mkdir(exist_ok=True)
IMAGE = 'alpine:3.20'


def cmd(*args, check=True):
    p = subprocess.run(['docker', *args], text=True, capture_output=True)
    row = {'command': ['docker', *args], 'exit': p.returncode,
           'stdout': p.stdout, 'stderr': p.stderr}
    with (OUT / 'docker-commands.jsonl').open('a') as f:
        f.write(json.dumps(row) + '\n')
    if check and p.returncode:
        raise RuntimeError(row)
    return row


def run(*args):
    return cmd('run', '--rm', '--runtime=runc', IMAGE, *args)['stdout'].strip()


def main():
    result = {'scope': 'Docker runc baseline only; no Kata or nerdctl results',
              'docker_info': json.loads(cmd('info', '--format', '{{json .}}')['stdout'])}
    result['kvm_probe'] = cmd('run', '--rm', '--privileged', IMAGE,
                             'sh', '-c', 'uname -r; ls -l /dev/kvm', check=False)
    result['kernel'] = run('uname', '-r')
    result['devices'] = int(run('sh', '-c', 'ls -1 /dev | wc -l'))
    result['caps'] = run('sh', '-c', 'grep ^CapEff /proc/1/status')
    run('true')
    result['startup_seconds'] = []
    for _ in range(5):
        start = time.perf_counter()
        run('true')
        result['startup_seconds'].append(time.perf_counter() - start)
    result['median_seconds'] = statistics.median(result['startup_seconds'])
    result['io'] = cmd('run', '--rm', '--runtime=runc', IMAGE, 'sh', '-c',
                      'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync')
    name = f'lab12-baseline-{time.time_ns()}'
    cmd('run', '-d', '--name', name, '--runtime=runc', IMAGE, 'sleep', '120')
    try:
        result['container_stats'] = json.loads(cmd('stats', '--no-stream', '--format',
                                                   '{{json .}}', name)['stdout'])
    finally:
        cmd('rm', '-f', name)
    # Bind only this disposable directory, never the host's entire /tmp.
    with tempfile.TemporaryDirectory(prefix='lab12-', dir='/tmp') as folder:
        target = Path(folder) / 'lab12-target'
        target.write_text('original\n')
        result['bind_test'] = cmd('run', '--rm', '--runtime=runc', '--privileged',
                                 '-v', folder + ':/host_tmp', IMAGE, 'sh', '-c',
                                 'echo OVERWRITTEN > /host_tmp/lab12-target')
        result['host_file_after'] = target.read_text()
    result['privileged'] = cmd('run', '--rm', '--runtime=runc', '--privileged', IMAGE,
                               'sh', '-c', 'ls -1 /dev | wc -l; grep ^CapEff /proc/1/status')
    (OUT / 'docker-baseline.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'docker_info'}, indent=2))


if __name__ == '__main__':
    main()
