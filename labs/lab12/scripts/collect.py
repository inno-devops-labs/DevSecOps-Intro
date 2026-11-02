#!/usr/bin/env python3
"""Collect actual runc/Kata evidence on a prepared Linux KVM host; never installs anything.

Run: sudo python3 labs/lab12/scripts/collect.py
Writes raw results and submissions/lab12-measurements.md. Adds --bonus for the
privileged write test. Both runtimes use --net=none for these offline workloads.
The write test is limited to a fresh temporary directory owned by this run.
"""
import argparse
import datetime
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
OUT = LAB / 'results'
ROOT = LAB.parents[1]
IMAGE = 'alpine:3.20'
RUNTIMES = {'runc': 'io.containerd.runc.v2', 'kata': 'io.containerd.kata.v2'}


def command(args, check=True):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    record = {'command': args, 'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    with (OUT / 'commands.jsonl').open('a') as f:
        f.write(json.dumps(record) + '\n')
    if check and p.returncode:
        raise RuntimeError(json.dumps(record, indent=2))
    return record


def run(rt, *args, check=True):
    return command(['nerdctl', 'run', '--rm', '--net=none', '--runtime=' + RUNTIMES[rt], IMAGE, *args], check)


def process_tree_pss(container_id):
    """Host PSS of the shim and all descendants, including guest VM and virtiofs.

    PSS apportions shared pages; guest /proc/meminfo or container stats alone
    would miss the hypervisor/kernel. Does not include shared containerd costs.
    """
    processes = {}
    roots = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            status = (proc / 'status').read_text()
            ppid = int(next(x.split()[1] for x in status.splitlines() if x.startswith('PPid:')))
            cmd = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            processes[int(proc.name)] = (ppid, cmd)
            if 'containerd-shim' in cmd and container_id in cmd:
                roots.append(int(proc.name))
        except (FileNotFoundError, ProcessLookupError, StopIteration):
            continue
    if len(roots) != 1:
        raise RuntimeError(f'Expected one shim for {container_id}; found {roots}')
    descendants = set(roots)
    while True:
        more = {pid for pid, (ppid, _) in processes.items() if ppid in descendants}
        if more <= descendants:
            break
        descendants |= more
    rows = []
    for pid in sorted(descendants):
        text = Path(f'/proc/{pid}/smaps_rollup').read_text()
        pss = int(next(x.split()[1] for x in text.splitlines() if x.startswith('Pss:')))
        rows.append({'pid': pid, 'command': processes[pid][1], 'pss_kib': pss})
    return {'total_pss_kib': sum(x['pss_kib'] for x in rows), 'processes': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bonus', action='store_true')
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    preflight = {'platform': platform.platform(), 'host_kernel': platform.release(),
                 'kvm_exists': Path('/dev/kvm').exists(),
                 'containerd': shutil.which('containerd'), 'nerdctl': shutil.which('nerdctl')}
    (OUT / 'preflight.json').write_text(json.dumps(preflight, indent=2) + '\n')
    if platform.system() != 'Linux' or not all(preflight[k] for k in ('kvm_exists', 'containerd', 'nerdctl')):
        raise SystemExit('Requires Linux, /dev/kvm, containerd and nerdctl; see results/preflight.json. No host changes made.')
    if os.geteuid() != 0:
        raise SystemExit('Run as root to access nerdctl and host PSS measurements.')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('/dev/kvm exists but is not accessible.')
    if (OUT / 'measurements.json').exists():
        raise SystemExit('Archive the previous results directory before collecting another run.')
    metadata = {'executed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'host': preflight, 'image': IMAGE, 'network': 'none'}
    for tool in ['containerd', 'nerdctl', 'runc', 'containerd-shim-kata-v2']:
        metadata[tool] = command([tool, '--version'])['stdout'].strip()
    version_file = Path('/opt/kata/VERSION')
    metadata['kata_assets'] = version_file.read_text() if version_file.exists() else 'VERSION file missing; see shim version'
    metadata['kata_configuration'] = Path('/etc/kata-containers/configuration.toml').read_text()
    metadata['qemu_version'] = command(['/opt/kata/bin/qemu-system-aarch64', '--version'])['stdout'].strip()
    command(['nerdctl', 'pull', IMAGE])  # Excluded from timings.
    metadata['image_inspect'] = command(['nerdctl', 'image', 'inspect', IMAGE])['stdout']
    results = {'metadata': metadata, 'runtimes': {}}
    try:
        for rt in RUNTIMES:
            print(f'Collecting {rt}: kernel, devices, capabilities, five startup samples, I/O, host PSS', flush=True)
            result = {}
            results['runtimes'][rt] = result
            result['kernel'] = run(rt, 'uname', '-r')['stdout'].strip()
            result['devices'] = int(run(rt, 'sh', '-c', 'ls -1 /dev | wc -l')['stdout'])
            result['cap_eff'] = run(rt, 'sh', '-c', 'grep ^CapEff /proc/1/status')['stdout'].strip()
            run(rt, 'true')  # Discard warm-up.
            result['startup_seconds'] = []
            for _ in range(5):
                start = time.perf_counter()
                run(rt, 'true')
                result['startup_seconds'].append(time.perf_counter() - start)
            result['startup_median_seconds'] = statistics.median(result['startup_seconds'])
            # Do not pipe dd to tail: a failed write must fail the collector.
            io = run(rt, 'sh', '-c', 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync')
            result['io'] = io['stdout'] + io['stderr']
            name = f'lab12-memory-{rt}-{os.getpid()}'
            cid = command(['nerdctl', 'run', '-d', '--net=none', '--name', name,
                           '--runtime=' + RUNTIMES[rt], IMAGE, 'sleep', '120'])['stdout'].strip()
            try:
                time.sleep(3)
                result['memory_samples'] = []
                for _ in range(5):
                    result['memory_samples'].append(process_tree_pss(cid))
                    time.sleep(1)
                result['median_host_pss_kib'] = statistics.median(
                    x['total_pss_kib'] for x in result['memory_samples'])
            finally:
                command(['nerdctl', 'rm', '-f', name], check=False)
        if args.bonus:
            results['bonus'] = {}
            # The mount and command are identical for both runtimes. Only runtime changes.
            # Bind only a disposable directory, rather than exposing all of host /tmp.
            with tempfile.TemporaryDirectory(prefix='lab12-', dir='/tmp') as directory:
                target = Path(directory) / 'lab12-target'
                for rt in RUNTIMES:
                    target.write_text('original\n')
                    result = command(['nerdctl', 'run', '--rm', '--net=none', '--runtime=' + RUNTIMES[rt],
                        '--privileged', '-v', directory + ':/host_tmp', IMAGE,
                        'sh', '-c', 'echo OVERWRITTEN > /host_tmp/lab12-target'], check=False)
                    result['host_file_after'] = target.read_text()
                    info = command(['nerdctl', 'run', '--rm', '--net=none', '--runtime=' + RUNTIMES[rt],
                        '--privileged', IMAGE, 'sh', '-c',
                        'ls -1 /dev | wc -l; grep ^CapEff /proc/1/status'], check=False)
                    result['privileged_devices_and_caps'] = info
                    results['bonus'][rt] = result
    finally:
        (OUT / 'measurements.json').write_text(json.dumps(results, indent=2) + '\n')
    report = ['# Lab 12 — Measured evidence', '',
              'Generated by `labs/lab12/scripts/collect.py` from this run only.', '',
              f'Host kernel: `{preflight["host_kernel"]}`.', '',
              '| Runtime | Kernel | Devices | CapEff | Startup median (s) | Host PSS (KiB) |',
              '|---|---|---:|---|---:|---:|']
    for rt, r in results['runtimes'].items():
        report.append(f'| {rt} | {r["kernel"]} | {r["devices"]} | {r["cap_eff"]} | '
                      f'{r["startup_median_seconds"]:.6f} | {r["median_host_pss_kib"]} |')
    for rt, r in results['runtimes'].items():
        report += ['', f'## {rt} raw measurements', '', 'Five startup times (seconds): ' +
                   ', '.join(f'{v:.6f}' for v in r['startup_seconds']), '', '```text', r['io'].strip(), '```']
    for rt, r in results.get('bonus', {}).items():
        report += ['', f'## {rt} privileged bind mount', '',
                   f'Exit code: {r["exit"]}; host file: `{r["host_file_after"].strip()}`.',
                   '', '```text', r['stderr'] + r['privileged_devices_and_caps']['stdout'], '```']
    (ROOT / 'submissions').mkdir(exist_ok=True)
    (ROOT / 'submissions/lab12-measurements.md').write_text('\n'.join(report) + '\n')
    print('Collected evidence in labs/lab12/results and submissions/lab12-measurements.md')


if __name__ == '__main__':
    main()
