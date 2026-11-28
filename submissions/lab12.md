# Lab 12 - VM-Backed Container Isolation with Kata

## Environment

- Host: Ubuntu 24.04.5 LTS, Intel
- Host kernel: `6.8.0-151-generic`
- KVM: available at `/dev/kvm`
- containerd: `2.2.1`
- nerdctl: `2.4.2`
- Kata Containers: `4.1.0`
- Kata hypervisor: Dragonball
- Image used: `alpine:3.20`

## Task 1 - Two runtimes, one image

| Measurement | runc | Kata |
|---|---|---|
| Kernel from `uname -r` | `6.8.0-151-generic` | `6.18.35` |
| Entries in `/dev` | 15 | 14 |
| `CapEff` | `00000000a80425fb` | `00000000a80425fb` |

A container using runc reports the host kernel release, which tells an attacker who has gained code execution which host-kernel version to research for weaknesses. Kata reports its guest kernel, `6.18.35`, instead of the host's `6.8.0-151-generic`, so this particular disclosure no longer identifies the host kernel. The default capability masks were identical in this run; the isolation difference comes from the guest-kernel boundary rather than a smaller default capability mask.

## Task 2 - What the isolation costs

### Startup times

One warm-up run was discarded, then five `nerdctl run --rm alpine:3.20 true` runs were timed with `/usr/bin/time -f '%e'`.

| Runtime | Five runs (seconds) | Median |
|---|---|---:|
| runc | 0.31, 0.31, 0.31, 0.31, 0.31 | 0.31 s |
| Kata | 1.18, 1.13, 1.16, 1.17, 1.16 | 1.16 s |

Kata took about 3.7 times as long as runc here, less than the roughly order-of-magnitude difference suggested in the lab prompt. A long-lived service or batch worker that runs for hours can amortize an extra second at startup. Short-lived serverless functions or rapidly scaling jobs pay that cost repeatedly. These timings include nerdctl and containerd overhead for both runtimes, as in the lab instructions.

### The I/O throughput

Each run wrote 512 MiB to `/tmp/bench` inside the container and used `conv=fsync`.

| Runtime | dd result |
|---|---|
| runc | 512 MiB in 0.480 s; 1.0 GB/s |
| Kata | 512 MiB in 2.039 s; 251.1 MB/s |

The command writes a file so the workload crosses the container storage layer; writing to `/dev/null` would measure discard speed instead of filesystem behavior.

### Memory

Two idle Alpine containers ran `sleep 300`; measurements were taken about eight seconds after startup. `nerdctl stats --no-stream` reported 416 KiB for runc and 1.449 MiB for Kata. For host-side runtime memory, `ps` reported the runc shim at 11,452 KiB RSS and the Kata shim at 181,852 KiB RSS, a difference of about 166 MiB. The Kata configuration uses Dragonball, whose VMM runs inside the Kata shim process, this RSS is a one-snapshot host-side estimate, not a repeated or peak-memory measurement.

### Workloads:

| Workload | Verdict | Reason |
|---|---|---|
| Untrusted multi-tenant build jobs or user-submitted code | Kata | A separate guest kernel adds a boundary between the workload and the host kernel. |
| Trusted, long-lived stateless API service | runc | Lower startup and memory costs suit a trusted service with many replicas. |
| Stateful database with sustained local I/O | Needs more information | The measured Kata filesystem throughput was lower, but the choice also depends on trust boundaries, storage design, and workload latency. |

## Bonus - Privileged container and host bind mount

| Runtime | Result of the privileged bind-mount command | Host file afterward | Privileged `/dev` / `CapEff` |
|---|---|---|---|
| runc | Succeeded; wrote `OVERWRITTEN` through `-v /tmp:/host_tmp` | `OVERWRITTEN` | 232 entries; `000001ffffffffff` |
| Kata 4.1.0, Dragonball, exact command | Failed before the container started: `get host path failed` / `No such file or directory` | `original` | Not available because the container did not start |
| Kata 4.1.0, Dragonball, with `--security-opt privileged-without-host-devices` | Succeeded; wrote `kata_privileged_ok` through `-v /tmp:/host_tmp` | `kata_privileged_ok` | 14 guest `/dev` entries; `000001ffffffffff` |

With runc, `--privileged` adds all capabilities and host devices to a container that shares the host kernel. The exact Kata command initially failed while trying to pass host devices; adding `--security-opt privileged-without-host-devices` let the privileged container start with 14 guest devices and all capabilities, which apply to the guest kernel. The writable `/tmp` bind mount still exposed the host file, which Kata changed to `kata_privileged_ok`; this is explicit shared-path access, not a kernel escape. Kata does not protect host files deliberately exposed through writable bind mounts or remove vulnerabilities in the hypervisor/runtime.

A supplemental Kata run with `--cap-add=ALL` but without `--privileged` also reported 14 `/dev` entries and `CapEff` `000001ffffffffff`. The Kata runtime logged `cannot set cgroup manager to "systemd"` during runs, containers still started for the unprivileged tests.