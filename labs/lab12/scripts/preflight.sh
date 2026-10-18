#!/usr/bin/env bash
# Run on the disposable Linux host before installing/reconfiguring Kata.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Linux is required' >&2; exit 1; }
[[ -c /dev/kvm ]] || { echo 'Missing /dev/kvm; do not substitute software emulation' >&2; exit 1; }
for tool in containerd nerdctl python3; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done
[[ $EUID == 0 ]] || { echo 'Run with sudo on the disposable Linux host' >&2; exit 1; }
python3 - <<'PY'
import fcntl
import os
import platform
fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
try:
    version = fcntl.ioctl(fd, 0xAE00)  # KVM_GET_API_VERSION
    assert version == 12, version
    print('Host:', platform.release(), platform.machine())
    print('/dev/kvm: opened read/write; KVM API version', version)
finally:
    os.close(fd)
PY
containerd --version
nerdctl --version
nerdctl info
