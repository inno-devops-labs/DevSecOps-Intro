#!/bin/zsh
set -euo pipefail

mkdir -p labs/lab9/{falco/{rules,logs},analysis}

docker rm -f falco lab9-helper eventgen 2>/dev/null || true

docker pull alpine:3.19 >/dev/null
docker pull falcosecurity/falco:latest >/dev/null
docker pull falcosecurity/event-generator:latest >/dev/null

docker run -d --name lab9-helper alpine:3.19 sleep 1d >/dev/null

docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U \
    -o json_output=true \
    -o time_format_iso_8601=true >/dev/null

sleep 15

docker exec lab9-helper /bin/sh -lc 'echo hello-from-shell' >/dev/null
docker exec --user 0 lab9-helper /bin/sh -lc 'mkdir -p /usr/local/bin && echo boom > /usr/local/bin/drift.txt' >/dev/null
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt' >/dev/null

docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall >/dev/null

sleep 10

docker logs falco --since 10m > labs/lab9/falco/logs/falco.log 2>&1
docker logs falco > labs/lab9/falco/logs/falco-full.log 2>&1 || true
docker inspect falco > labs/lab9/falco/logs/falco-inspect.json

docker rm -f falco lab9-helper 2>/dev/null || true

echo "falco_done"
