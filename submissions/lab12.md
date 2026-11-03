# Lab 12 — VM-Backed Container Isolation with Kata

## Task 1

Both runtimes used the same `alpine:3.20` image.

| Observation | Host | runc container | Kata container |
| --- | --- | --- | --- |
| Kernel release | `6.8.0-147-generic` | `6.8.0-147-generic` | `6.18.35` |
| Entries in `/dev` | — | 15 | 14 |
| `CapEff` | — | `00000000a80425fb` | `00000000a80425fb` |

The runc output tells an attacker that this container shares the host's
`6.8.0-147-generic` kernel, identifying a concrete kernel build to investigate
for applicable vulnerabilities. The release string alone does not prove that
an exploit works, since patches, configuration and available privileges also
matter. Kata instead reports its `6.18.35` guest kernel, so a guest-kernel
compromise would still face the VM boundary before reaching the outer Linux
host. Identical capability masks do not remove that distinction: capabilities
operate against different kernels in the two cases.

## Task 2

Measurements used Kata 4.1.0 Go/QEMU with virtio-fs under nested virtualization,
configured with 1 vCPU and 1,024 MiB guest RAM.

After one discarded warm-up per runtime, `/usr/bin/time -f '%e'` measured five
`alpine:3.20 true` runs in seconds, including nerdctl, containerd and container
lifecycle overhead for both runtimes.

| Runtime | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| runc | 0.42 s | 0.43 s | 0.41 s | 0.43 s | 0.50 s | **0.43 s** |
| Kata | 2.19 s | 3.15 s | 2.18 s | 4.62 s | 4.85 s | **3.15 s** |

I/O was measured with one 512 MiB file write per runtime using `conv=fsync`.

| Runtime | Throughput (MiB/s) |
| --- | ---: |
| runc | 602.4 |
| Kata | 95.0 |

Writing to a file exercises the container storage path, including Kata's
virtio-fs boundary, whereas `/dev/null` would discard the data without measuring
that path.

Memory was measured five seconds after launching one idle `alpine:3.20 sleep 300`
container at a time, summing `/proc/PID/smaps_rollup` PSS for its shim, workload
or QEMU, virtiofsd and logging helpers; the common containerd daemon was excluded.
These figures estimate idle host-process memory and do not account for all
kernel allocations or filesystem cache.

| Runtime | PSS (MiB) |
| --- | ---: |
| runc | **39.73** |
| Kata | **306.23** |
| Additional footprint for Kata | **266.50** |

| Workload | Verdict | Reason |
| --- | --- | --- |
| Long-running CI workers executing tenant-supplied code | Kata | A separate guest kernel is useful for untrusted code, and infrequent starts amortize the startup cost. |
| Trusted internal API with controlled images and frequent scaling | runc | The lower measured startup and memory costs suit this workload when the threat model accepts a shared kernel. |
| Untrusted, I/O-heavy batch processing | needs more information | The isolation benefit must be weighed against representative I/O measurements, job duration and the latency budget. |

For long-lived background workers whose startup is outside the request path,
the startup cost is amortized over hours of work. Although Kata's median was
7.33× higher, the additional 2.72 seconds may be operationally negligible for
that workload. The same delay can matter for short-lived jobs or scale-out on
a request's critical path.

## Bonus

The prescribed commands were run with the original device view, using Kata
4.1.0 Rust/Dragonball for this initial comparison:

```bash
printf 'original\n' > /tmp/lab12-target
sudo -n nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
cat /tmp/lab12-target

printf 'original\n' > /tmp/lab12-target
sudo -n nerdctl run --rm --runtime=io.containerd.kata.v2 \
  --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
cat /tmp/lab12-target
```

| Observation | runc, privileged | Kata Rust/Dragonball, privileged |
| --- | --- | --- |
| Write command outcome | Completed | Failed during device setup: `get host path failed`, `No such file or directory` |
| Host file after (`cat /tmp/lab12-target`) | `OVERWRITTEN` | `original` |
| Entries in `/dev` | 188 | Unavailable: container creation failed |
| `CapEff` | `000001ffffffffff` | Unavailable: container creation failed |

An additional bind-mount comparison repeated the commands above with Kata
4.1.0 Go/QEMU and a private CLI mount namespace applied to both runtimes.
Six standard `/dev` nodes were exposed as symlinks to avoid duplicate device
creation; the results below belong to this adapted setup.

| Observation | runc, privileged | Kata Go/QEMU, privileged |
| --- | --- | --- |
| Host file after | `OVERWRITTEN` | `OVERWRITTEN` |
| Entries in `/dev` | 189 | 187 |
| `CapEff` | `000001ffffffffff` | `000001ffffffffff` |

Under runc, `--privileged` grants broad capabilities against the shared host
kernel and exposes host devices; under Kata, capabilities act against the guest
kernel. In the original Kata run, the file remained unchanged because container
creation failed before the write, which does not demonstrate escape containment.
In the adapted comparison, both runtimes overwrote the file because `/tmp` was
explicitly exported read-write, demonstrating shared-storage access rather than
a guest-kernel escape.

Kata does not protect host files deliberately exposed through writable mounts.
