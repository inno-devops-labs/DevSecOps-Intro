#!/usr/bin/env python3
"""Probe host-PID isolation, intentionally shared storage, and guest capabilities.

Run as root on the prepared Linux KVM VM after collect.py. Every write is confined
to a directory created by this run; no macOS directories are mounted in the VM.
Both runtimes receive identical flags apart from the runtime selection.
"""
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

RUNTIMES = {'runc': 'io.containerd.runc.v2', 'kata': 'io.containerd.kata.v2'}


def run(runtime, flags, script):
    command = ['nerdctl', 'run', '--rm', '--net=none', '--runtime=' + runtime,
               *flags, 'alpine:3.20', 'sh', '-c', script]
    p = subprocess.run(command, text=True, capture_output=True, timeout=180)
    return {'command': command, 'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}


def main():
    if platform.system() != 'Linux' or os.geteuid() != 0 or not Path('/dev/kvm').exists():
        raise SystemExit('Run as root inside the prepared Linux KVM lab VM.')
    results = {'host_pid': {}, 'writable_bind': {}, 'all_caps': {}}
    with tempfile.TemporaryDirectory(prefix='lab12-boundary-', dir='/tmp') as folder:
        target = Path(folder) / 'target'
        for rt, runtime in RUNTIMES.items():
            target.write_text('original\n')
            result = run(runtime, ['--cap-add=SYS_PTRACE', '--pid=host',
                                  '--security-opt=apparmor=unconfined'],
                         f'echo OVERWRITTEN > /proc/1/root{target}')
            result.update(host_file_before='original\n', host_file_after=target.read_text())
            results['host_pid'][rt] = result
            print(rt, 'host-PID exit', result['exit'], 'host file:', target.read_text().strip(), flush=True)
            target.write_text('original\n')
            result = run(runtime, ['-v', folder + ':/host_tmp'],
                         'echo OVERWRITTEN > /host_tmp/target')
            result.update(host_file_before='original\n', host_file_after=target.read_text())
            results['writable_bind'][rt] = result
            print(rt, 'writable bind exit', result['exit'], 'host file:', target.read_text().strip(), flush=True)
            results['all_caps'][rt] = run(runtime, ['--cap-add=ALL'],
                                          'ls -1 /dev | wc -l; grep ^CapEff /proc/1/status')
    out = Path(__file__).resolve().parents[1] / 'results/boundaries.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + '\n')
    assert results['host_pid']['runc']['exit'] == 0
    assert results['host_pid']['runc']['host_file_after'] == 'OVERWRITTEN\n'
    assert results['host_pid']['kata']['exit'] != 0
    assert results['host_pid']['kata']['host_file_after'] == 'original\n'
    assert all(r['exit'] == 0 and r['host_file_after'] == 'OVERWRITTEN\n'
               for r in results['writable_bind'].values())
    assert all(r['exit'] == 0 for r in results['all_caps'].values())
    print('PASS: runc host-PID write, Kata host-PID isolation, explicit writable shares, all-capability probes')


if __name__ == '__main__':
    main()
