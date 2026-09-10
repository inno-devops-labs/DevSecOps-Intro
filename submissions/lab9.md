# Lab 9 — Runtime + Policy as Code

## Task 1

### Built-in rules (requires Linux/eBPF host)
Falco on Docker Desktop macOS does not expose the host kernel; run Task 1 on Linux/Colima/`--vm-type vz` or WSL2 and paste:

```bash
docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
```

Expected after `docker exec -t lab9-target ...` and `cat /etc/shadow`: terminal shell + sensitive file rules.

### Custom rule
See `labs/lab9/falco/rules/custom-rules.yaml` (`Write Below Tmp In Container` + cryptominer bonus).

## Task 2

### Conftest counts
| Manifest | Result |
|----------|--------|
| juice-hardened.yaml | 34 tests, 33 passed, 1 warning, 0 failures |
| juice-unhardened.yaml | 34 tests, 22 passed, 3 warnings, 9 failures |
| juice-compose.yml | 17 tests, 17 passed |

Example unhardened failures mapped to Rego: `runAsNonRoot` / `allowPrivilegeEscalation` / `:latest` → `k8s.security` denies; missing digest pin → `extra.hardening` deny.

Compose needs its own Rego because the schema (`services:` vs `Deployment`) differs; Compose passing shows the Compose policy is not a no-op.

### Extra policy
`labs/lab9/policies/extra/hardening.rego` + violator `labs/lab9/manifests/k8s/juice-violates-extra.yaml` (fails digest pin + warn on automount).

If only one control: keep **Conftest in CI** for the digest pin (blocks merge); Falco still catches runtime drift the manifest never promised.

## Bonus
Cryptominer rule included in `custom-rules.yaml` (CRITICAL, pool ports + process signals). Trigger with `nc -w 2 127.0.0.1 3333` on a Linux Falco host.
