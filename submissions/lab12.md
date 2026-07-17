# Lab 12 — BONUS — Submission

## Task 1: Kata Installation and Runtime Comparison

### Test host

| Component | Observed value |
|---|---|
| Host kernel | Ubuntu `6.17.0-40-generic`, x86_64, host `Verdrum` |
| KVM device | Present as `/dev/kvm`, character device `10:232`, owned by `root:kvm`, mode `crw-rw----+` |
| containerd | `containerd github.com/containerd/containerd/v2 v2.3.2` |
| Kata Containers | `3.32.0` |

KVM was available to the runtime through `/dev/kvm`.

### Kata registration in containerd

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel reported by each runtime

The default runc container produced:

```text
Linux a3f7c2194d60 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 16 14:24:32 UTC 2026 x86_64 Linux
processor    : 0
vendor_id    : AuthenticAMD
cpu family   : 25
```

The Kata container produced:

```text
Linux e91a45c7b302 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor    : 0
vendor_id    : AuthenticAMD
cpu family   : 25
```

### Interpretation

The runc result repeats the host kernel version because an ordinary container is
a group of host processes isolated with namespaces and cgroups. Kata reports a
different kernel, `6.18.35`, because the workload executes inside a KVM-backed
micro-VM. Consequently, attacks that depend on a shared host kernel or vulnerable
runc state meet an additional VM boundary; CVE-2024-21626 is an example of the
runc escape class discussed in the course, although it is a runtime flaw rather
than a Linux-kernel vulnerability.

## Task 2: Isolation Evidence and Performance

### `/dev` comparison

```text
1d0
< core
```

In this run, `core` appeared only in the runc device listing. The difference is
small, but it confirms that the two containers did not receive an identical
device view: Kata constructs devices for the guest VM instead of exposing the
same device environment used by runc.

### Linux capability masks

**runc:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

**Kata:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The masks are identical because both containers were created from the same OCI
security settings. Their scope is still different: runc capabilities are handled
by the host kernel, while the Kata process exercises them against the guest
kernel inside the micro-VM.

### Container startup time

| Runtime | Mean of five runs |
|---|---:|
| runc | 0.657 s |
| Kata | 2.152 s |

The measured Kata startup was approximately **3.28 times slower**. Image download
time was not included in these measurements.

### `dd` throughput

| Runtime | Reported throughput |
|---|---:|
| runc | 8.4 GB/s |
| Kata | 1.8 GB/s |

For this 100 MB test, Kata reached roughly **21% of the runc throughput**; stated
the other way around, runc was about **4.7 times faster**. The command copies
zero-filled data to `/dev/null`, so the result is a small synthetic comparison
rather than a complete storage benchmark, but it still exposes additional work
inside the virtualized execution path.

### Deployment trade-off

I would select Kata for workloads whose input cannot be trusted, such as shared
CI runners, student code-execution systems, and customer-provided extensions.
For these cases, the separate guest kernel is worth several seconds of startup
latency because a compromised workload does not immediately share the host's
kernel boundary. I would keep runc for trusted single-tenant services, short-lived
latency-sensitive jobs, and I/O-heavy workloads where the measured overhead is
more important than the extra isolation. A mixed deployment is therefore more
reasonable than replacing runc everywhere: ordinary services can remain on
runc, while only high-risk workloads use Kata.

## Bonus: Privileged Host-Write Attempt

### Selected vector

I used option B: a privileged container with a writable bind mount of the host's
`/tmp` directory. This represents a realistic configuration error because a
compromised CI job or Kubernetes workload with equivalent privileges could use
an exposed host path for persistence or host modification.

### runc result

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

The result was then checked from the host:

```bash
sudo cat /tmp/lab12-target
```

```text
OVERWRITTEN BY RUNC CONTAINER
```

The external check confirms that the write was not confined to the container's
overlay filesystem: runc modified the host file through the explicitly mounted
directory.

### Kata result

After restoring the target file to `original`, I repeated the attempt with the
Kata runtime:

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 \
  --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target'
```

The workload did not start. The relevant runtime error was:

```text
failed to create shim task: Creating container device LinuxDevice { path: "/dev/full" }
Caused by: EEXIST: File exists
```

Host-side verification still returned:

```bash
sudo cat /tmp/lab12-target
```

```text
original
```

### Security interpretation and limitations

The runc write succeeded because the command deliberately combined full
container privileges with a writable host directory. On this Kata setup, the
same attempt was stopped earlier: creation of the privileged guest device set
failed on `/dev/full`, so the payload never ran and the host file remained
unchanged. This evidence should not be overstated as proof that every writable
bind mount becomes harmless under Kata—host-backed paths can still be shared
through mechanisms such as virtio-fs, and access to them must be restricted by
policy. Kata's main security gain is the separate guest-kernel boundary; it does
not eliminate risks from explicitly shared host resources, hypervisor defects,
CPU side channels, timing attacks, or a malicious host, some of which belong to
the different threat model addressed by Confidential Containers.

## Completion Checklist

- [x] Kata 3.32.0 installed and registered with containerd.
- [x] runc and Kata workloads executed with visibly different kernels.
- [x] Device and capability evidence recorded for both runtimes.
- [x] Five-run startup averages calculated.
- [x] Required 100 MB `dd` comparison recorded.
- [x] runc host modification verified outside the container.
- [x] Kata attempt recorded and host state checked afterward.
- [x] Performance trade-offs and residual risks discussed.
