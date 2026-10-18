#!/usr/bin/env bash
# After unpacking official kata-go-static-4.1.0-arm64.tar.zst in a disposable VM.
set -euo pipefail
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || {
  echo 'Run as root inside the disposable ARM64 Linux/KVM VM' >&2; exit 1;
}
[[ -c /dev/kvm ]] || { echo '/dev/kvm is required' >&2; exit 1; }
[[ $(cat /opt/kata/VERSION) == 4.1.0 ]] || { echo 'Expected Kata 4.1.0' >&2; exit 1; }
/opt/kata/bin/containerd-shim-kata-v2 --version
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_config=/opt/kata/share/defaults/kata-containers/configuration-qemu.toml
live_config=/etc/kata-containers/configuration.toml
[[ -f "$source_config" ]] || { echo "Unpack the complete official Go archive first" >&2; exit 1; }
mkdir -p /etc/kata-containers
if [[ -f "$live_config" ]]; then
  cp -a "$live_config" "${live_config}.$(date +%Y%m%d%H%M%S).bak"
fi
cp "$source_config" "$live_config"
# Direct boot; the parent VZ VM does not expose a PMU. gicv2m delivers MSI as
# SPIs instead of using the nested ITS path. It retains PCIe hotplug and KVM.
python3 - "$live_config" <<'PY'
from pathlib import Path
import re
import sys
import tomllib
p = Path(sys.argv[1])
s = p.read_text()
for key, value in {'cpu_features': '', 'firmware': '', 'firmware_volume': '',
                   'machine_accelerators': 'msi=gicv2m'}.items():
    s, n = re.subn(r'^' + key + r' = .*$', f'{key} = "{value}"', s, flags=re.M)
    assert n == 1, (key, n)
data = tomllib.loads(s)
assert data['hypervisor']['qemu']['machine_accelerators'] == 'msi=gicv2m'
p.write_text(s)
PY
# Lima's Ubuntu image creates two block nodes for the same root partition.
# Kata 4.1 rejects duplicate host major/minor updates under --privileged.
# Preserve /dev/root as a conventional symlink to the identical device.
python3 - <<'PY_ALIAS'
from pathlib import Path
import stat
alias = Path('/dev/root')
canonical = Path('/dev/vda1')
if alias.exists() and not alias.is_symlink():
    old = alias.stat()
    target = canonical.stat()
    assert stat.S_ISBLK(old.st_mode) and stat.S_ISBLK(target.st_mode)
    assert old.st_rdev == target.st_rdev, 'Refusing to change a different root device'
    staged = Path('/dev/root.lab12-symlink')
    staged.symlink_to(canonical.name)
    staged.replace(alias)
    assert alias.stat().st_rdev == old.st_rdev
    print('Normalized /dev/root -> vda1; block device identity preserved')
PY_ALIAS
# Kata rustjail creates six default devices before the OCI host-device list.
# Keep every host device exposed at a canonical path, with the conventional
# paths as symlinks, avoiding a duplicate mknod/EEXIST inside the guest.
python3 - <<'PY_CHAR'
from pathlib import Path
import os, stat
canonical = Path('/dev/lab12-host-devices')
canonical.mkdir(exist_ok=True)
for name, minor in [('null',3),('zero',5),('full',7),('random',8),('urandom',9),('tty',0)]:
    original = Path('/dev') / name
    target = canonical / name
    before = original.stat()
    assert stat.S_ISCHR(before.st_mode)
    assert os.major(before.st_rdev) == (5 if name == 'tty' else 1)
    assert os.minor(before.st_rdev) == minor
    if not original.is_symlink():
        os.mknod(target, before.st_mode, before.st_rdev)
        os.chown(target,before.st_uid,before.st_gid)
        os.chmod(target,stat.S_IMODE(before.st_mode))
        staged = Path(str(original)+'.lab12-symlink')
        staged.symlink_to('lab12-host-devices/'+name)
        staged.replace(original)
    assert original.stat().st_rdev == before.st_rdev
print('PASS: six standard device aliases preserve major/minor and permissions')
PY_CHAR
ln -sfn /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
bash "$root_dir/scripts/configure-containerd-kata.sh"
containerd --config /etc/containerd/config.toml config dump >/dev/null
sysctl -w net.ipv4.ip_forward=1
systemctl restart containerd
/opt/kata/bin/kata-runtime --version
