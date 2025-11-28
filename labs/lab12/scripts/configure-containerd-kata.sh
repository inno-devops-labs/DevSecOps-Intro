#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/containerd/config.toml"

if [ ! -f "${CONF}" ]; then
  echo "[lab12] ERROR: ${CONF} not found."
  echo "[lab12] Run: sudo containerd config default | sudo tee /etc/containerd/config.toml >/dev/null"
  exit 1
fi

echo "[lab12] Backing up ${CONF} ..."
sudo cp "${CONF}" "${CONF}.bak.$(date +%s)"

# best-effort: удалить старые блоки kata, чтобы не плодить дубликаты
sudo sed -i '/\[plugins\."io.containerd.cri.v1.runtime"\.containerd\.runtimes\.kata\]/,/^\s*$/d' "${CONF}" || true
sudo sed -i '/\[plugins\."io.containerd.grpc.v1.cri"\.containerd\.runtimes\.kata\]/,/^\s*$/d' "${CONF}" || true

if grep -q 'plugins."io.containerd.cri.v1.runtime"' "${CONF}"; then
  cat << 'EOCFG' | sudo tee -a "${CONF}"

# Added by lab12 (Kata runtime, v3 config)
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
EOCFG
else
  cat << 'EOCFG' | sudo tee -a "${CONF}"

# Added by lab12 (Kata runtime, legacy config)
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
EOCFG
fi

echo "[lab12] Updated ${CONF} with Kata runtime."
