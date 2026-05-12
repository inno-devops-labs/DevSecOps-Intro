# Task 1

## Top 5 Critical/High Vulnerabilities
|CVE ID|	Affected package|	Severity|	Impact|
|-|-|-|-|
|CVE-2026-44006|	vm2 3.9.17|	Critical, CVSS 10.0|	Code injection may allow severe sandbox compromise and arbitrary code execution|
|CVE-2026-44005|	vm2 3.9.17|	Critical, CVSS 10.0|	Prototype pollution can corrupt application state and enable follow-on exploitation|
|CVE-2026-43997|	vm2 3.9.17|	Critical, CVSS 10.0|	Code injection creates a high-risk path to full runtime compromise|
|CVE-2026-44009|	vm2 3.9.17|	Critical, CVSS 9.8	|Resource exposure may break isolation boundaries and expose sensitive execution context|
|CVE-2026-44008|	vm2 3.9.17|	Critical, CVSS 9.8	|Resource exposure can undermine containment and significantly increase compromise impact|

## Dockle
... didn't find any FATAL or WARN: 
```shell
Status: Downloaded newer image for goodwithtech/dockle:latest
SKIP    - DKL-LI-0001: Avoid empty password
        * failed to detect etc/shadow,etc/master.passwd
INFO    - CIS-DI-0005: Enable Content trust for Docker
        * export DOCKER_CONTENT_TRUST=1 before docker pull/build
INFO    - CIS-DI-0006: Add HEALTHCHECK instruction to the container image
        * not found HEALTHCHECK statement
INFO    - DKL-LI-0003: Only put necessary files
        * unnecessary file : juice-shop/node_modules/micromatch/lib/.DS_Store 
        * unnecessary file : juice-shop/node_modules/extglob/lib/.DS_Store
```

## Security Posture Assessment
- Run as root? seemingly no, instead used some user 65532
- Upgrade vm2 3.9.17 because it has multiple possibly patched CVEs
- Update components

# Task 2
For some reason, provided command didn't work for my installation...
```shell
docker: invalid reference format
```

# Task 3 

## Configuration Comparison Table
| Profile | Functionality | Capabilities | Security options | Memory | CPU | PIDs | Restart |
|---|---:|---|---|---:|---:|---:|---|
| Default | HTTP 200 | Docker default | Docker default | Unlimited | Unlimited | Unlimited | no |
| Hardened | HTTP 200 | Drop ALL | no-new-privileges | 512 MiB | 1 CPU | Unlimited | no |
| Production | HTTP 200 | Drop ALL, add NET_BIND_SERVICE | no-new-privileges | 512 MiB | 1 CPU | 100 | on-failure |

## Security Measure Analysis

### `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
Linux capabilities are small privilege blocks; dropping them limits what a compromised container can do.
``NET_BIND_SERVICE`` adds back only permission to bind low ports, so security stays tighter than Docker defaults.

### ``--security-opt=no-new-privileges``
Prevents processes from gaining extra privileges after startup.

### ``--memory=512m`` and ``--cpus=1.0``
Limits memory usage to 512M and CPU usage to 1

### ``--pids-limit=100``
Anti-fork-bomb limit to only 100 subprocesses

### ``--restart=on-failure:3``
Restart the container on crash, but only up to 3 times


## 3. Critical Thinking Questions

- Development: Use the Default profile because it is easiest for debugging and has fewer restrictions.
- Production: Use the Production profile because it applies least privilege, resource limits, PID limits, and controlled restart behavior.
- Resource limits: They prevent one container from exhausting host resources and degrading other services.
- Default vs Production: Production blocks extra Linux capabilities, privilege escalation, excessive memory use, excessive process creation, and unlimited restart loops.
- Additional hardening: Add a read-only root filesystem, explicit non-root user validation, image signing, dependency patching, and stricter network exposure.
