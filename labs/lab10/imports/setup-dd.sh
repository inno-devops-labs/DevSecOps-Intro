#!/bin/bash
# Start DefectDojo locally (first run ~5-10 min)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$ROOT/work"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [[ ! -d dd ]]; then
  echo "Cloning DefectDojo..."
  git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo dd
fi

cd dd
./docker/setEnv.sh dev
docker compose pull
docker compose up -d

echo ""
echo "Waiting for initializer (admin password)..."
sleep 15
docker compose logs initializer 2>&1 | grep -i password | tail -3 || true
echo ""
echo "UI: http://localhost:8080"
echo "Then: Profile → API v2 Key → export DD_TOKEN"
echo "      cp labs/lab10/imports/env.sample labs/lab10/imports/env.sh && edit"
echo "      source labs/lab10/imports/env.sh"
echo "      bash labs/lab10/imports/run-imports.sh"
