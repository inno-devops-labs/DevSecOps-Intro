#!/usr/bin/env bash
# Run as root INSIDE a fresh disposable Lima ARM64 Linux VM, never on macOS.
# Uses the supported Go/QEMU release asset rather than the starter's runtime-rs defaults.
set -euo pipefail
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && -c /dev/kvm ]] || {
  echo 'Requires aarch64 Linux with /dev/kvm; create the nested Lima VM first.' >&2
  exit 1
}
[[ $EUID == 0 ]] || { echo 'Run as root inside the disposable VM.' >&2; exit 1; }
[[ ! -e /opt/kata && ! -e /etc/kata-containers/configuration.toml ]] || {
  echo 'Kata assets/configuration already exist; use a fresh disposable VM.' >&2
  exit 1
}
command -v containerd >/dev/null
# Lima provides nerdctl, containerd, runc and CNI; add extraction/collection tools.
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl zstd python3
archive=$(mktemp --suffix=.tar.zst)
trap 'rm -f "$archive"' EXIT
curl -fL --retry 3 -o "$archive" \
  https://github.com/kata-containers/kata-containers/releases/download/4.1.0/kata-go-static-4.1.0-arm64.tar.zst
printf '%s  %s\n' 9008fa1acdc6e9f5c86e9f4fa0e22dbaf09106f8ddc62383bfcb7cfa0df42ff3 "$archive" | sha256sum -c -
tar --zstd -xf "$archive" -C /
mkdir -p /etc/kata-containers
cp /opt/kata/share/defaults/kata-containers/configuration-qemu.toml \
  /etc/kata-containers/configuration.toml
python3 - <<'PY'
from pathlib import Path
p = Path('/etc/kata-containers/configuration.toml')
s = p.read_text()
changes = {
    'cpu_features = "pmu=off"': 'cpu_features = ""',
    'firmware = "/opt/kata/share/aavmf/AAVMF_CODE.fd"': 'firmware = ""',
    'firmware_volume = "/opt/kata/share/aavmf/AAVMF_VARS.fd"': 'firmware_volume = ""',
    'disable_image_nvdimm = false': 'disable_image_nvdimm = true',
    'machine_accelerators = ""': 'machine_accelerators = "highmem-mmio=off"',
    'kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"':
        'kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 pci=nomsi"',
}
for old, new in changes.items():
    if s.count(old) != 1:
        raise SystemExit(f'Pinned configuration does not contain exactly one {old!r}')
    s = s.replace(old, new)
p.write_text(s)
PY
ln -s /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$script_dir/../scripts/configure-containerd-kata.sh"
containerd config dump >/tmp/lab12-containerd-effective.toml
systemctl restart containerd
/opt/kata/bin/kata-runtime check
nerdctl run --rm --net=none --runtime=io.containerd.kata.v2 alpine:3.20 uname -r
