# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
<!-- Получить командой:
jq '[.Results[].Vulnerabilities[]?] | group_by(.Severity) | map({severity: .[0].Severity, total: length, with_fix: (map(select(.FixedVersion != null)) | length)})' \
  labs/lab7/results/trivy-image.json
-->
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | <n> | <m> |
| High | <n> | <m> |
| **Total** | <n> | <m> |

### Top 10 CVEs with fixes
<!-- Вывод команды из 7.3, вставить как таблицу -->
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| ... | ... | ... | ... | ... |

### Compared to Lab 4's Grype scan
<!--
1. CVE, которое нашли ОБА инструмента: <CVE-ID> — почему совпало (обычно: широко известная CVE
   в популярном пакете, обе БД её давно проиндексировали).
2. CVE, которое нашёл только ОДИН инструмент: <CVE-ID> — объяснить через:
   - разницу во времени обновления БД (Trivy/Grype тянут из разных источников: NVD, GHSA,
     дистро-security-advisories — Alpine/Debian/etc.)
   - разный package matching (бинарный vs. build-manifest matching, разные эвристики версий)
   - EPSS-скоринг может влиять на то, что один инструмент фильтрует/приоритизирует иначе
-->
1. **Найдено обоими:** `<CVE-XXXX-XXXXX>` — ...
2. **Найдено только одним:** `<CVE-XXXX-XXXXX>` (найден в: Trivy/Grype) — ...

---

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext sections (pod + container):
```yaml
# pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault

# container-level
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

`networkpolicy.yaml` ingress + egress:
```yaml
# ingress: только TCP/3000 из namespace
# egress: DNS (UDP/TCP 53 -> kube-system) + HTTPS (TCP 443)
```

### Pod is running
<!-- Вставить вывод: kubectl get pod -n juice-shop -l app=juice-shop -->
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-xxxxxxxxxx-xxxxx   1/1     Running   0          2m
```

### Trivy K8s scan
<!-- Вставить из trivy k8s --report=summary -->
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |

### What broke and how you fixed it
`readOnlyRootFilesystem: true` ломает Juice Shop, потому что приложение пишет во
время работы в `/tmp`, `/usr/src/app/logs` и `/usr/src/app/data` (там лежит
SQLite-база `juiceshop.sqlite`). Исправлено через три `emptyDir{}`-volume,
смонтированных на эти пути (см. `deployment.yaml`), так что файловая система
контейнера остаётся read-only, а запись уходит во временные in-memory/tmpfs
тома, которые не персистентны между рестартами пода.

---

## Bonus: Conftest Policy

### Policy
```rego
<!-- вставить полный файл labs/lab7/policies/pod-hardening.rego -->
```

### Output: PASS on hardened manifest
<!-- conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies -->
```
0 tests, 0 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
<!-- conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies -->
```
FAIL - /tmp/bad-pod.yaml - main - bad-app: container 'app' has no securityContext defined at all
...
```

### What this prevents at CI time
Политика ловит структурные ошибки hardening (root-контейнеры, writable rootfs,
lack of capability-dropping) ещё на этапе CI/PR — до того, как манифест вообще
попадёт в кластер. Это дешевле и быстрее, чем ловить то же самое на этапе
admission control (PSS/OPA Gatekeeper), потому что: (1) обратная связь
разработчику приходит за секунды в PR-check, а не при деплое; (2) неудачный
`kubectl apply` на проде/staging может частично применить ресурсы и потребовать
отката; CI-gate просто не даёт смёрджить PR.
