# Lab 12 — VM-Backed Container Isolation with Kata

## Task 1

| Kernels | Versions |
|--|--|
| Host | 6.8.0-139-generic |
| runc | 6.8.0-139-generic |
| Kata | 6.18.35 |

| Runtime | Device count | Capabilities |
|--|--|--|
| runc | 15 | 00000000a80425fb |
| Kata | 14 | 00000000a80425fb |

On runc the kernel is the same as the host. This is allowing the attacker to identify all the host's known vulnerabilities.
However they have no way to know that if Kata's used instead, because they dont match.



## Task 2

| n | runc | kata |
|--|--|--|
| 1 | 0.1 | 8.77 |
| 2 | 0.11 | 8.78 |
| 3 | 0.11 | 8.76 |
| 4 | 0.12 | 8.79 |
| 5 | 0.1 | 8.76 |
| median | 0.11 | 8.77 |

| Runtime | Result |
|--|--|
| runc | 2.2 GB/s |
| Kata | 0.6 GB/s |

You write to a file because /dev/null never touches the file system stack that differs between runc and runtime.

| Runtime | memory current |
|--|--|
| runc | 339 968 B |
| Kata | 491 384 832 B |

469 mb overhead per sandbox against runcs hundreds of KiB.

| Workload | Verdict | Why |
|--|--|--|
| Stateless APIs and cold-start sensitive | runc | Median start of 0.11s, memory density |
| CI with forbidden host mounts | Kata | Second kernel contains kernel exploits |
| GPU training with vendors | more info | Device passthrough and driver support dominate and neither is automatic |

The difference doesnt matter for services running for hours and days. That includes stuff like databases and such. These seconds wont matter at all.

## Bonus

| Exact test | runc | Kata |
|--|--|--|
| Exit status | 0 | 1 |
| Host file | OVERWRITTEN | original |
| entry count | 192 | container creation failed |
| PID | 000001ffffffffff | no container process started |


On runc it expands the container’s view to all the dev nodes and a full capability mask, and a bind mount is the host filesystem. On kata it grants privileges inside the guest kernel, not over the host. In this environment the privileged create path got aborted before writing, and the host file stayed original.


Honest limit: Kata does not stop a workload that you share host paths on your own, an unprivileged Kata container did write FROM_KATA to the host. Its just a second kernel and not a cure all.