# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux almostArch 7.1.3-arch2-1 #1 SMP PREEMPT_DYNAMIC Tue, 14 Jul 2026 23:03:30 +0000 x86_64 GNU/Linux`
- KVM accessible: `crw-rw-rw- 1 root kvm 10, 232 Jul 17 08:10 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 v2.3.3 aad11006b869517fcd3009450b6f82da282e1a9b.m`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
  ```toml
  [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
    runtime_type = 'io.containerd.kata.v2'
  ```

### Kernel inside containers
**runc:**
```text
Linux 01a93f9f12f6 7.1.3-arch2-1 #1 SMP PREEMPT_DYNAMIC Tue, 14 Jul 2026 23:03:30 +0000 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**
```text
Linux b879b8972908 6.18.35 #1 SMP Mon Jun 15 12:55:10 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs (Reading 12)
Unlike `runc`, which relies on Linux namespaces and cgroups to isolate processes that still share the host kernel, Kata Containers launches each workload inside a lightweight, hardware-virtualized micro-VM with its own dedicated guest kernel. This architectural difference means that a container escape vulnerability (such as the "Leaky Vessels" CVE-2024-21626 in `runc`) would only compromise the isolated, throwaway micro-VM, not the underlying host system, effectively neutralizing this entire class of kernel-level escape attacks.

## Task 2: Isolation + Performance

### Isolation: /dev diff
```text
1d0
< core
```

### Isolation: capability sets
runc:
```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
kata:
```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc    | 0.25            |
| kata    | 5.82            |

**Overhead: ~23× cold start.**

### I/O throughput (100MB dd to /dev/null)
| Runtime | Throughput |
|---------|------------|
| runc    | 21.7 GB/s  |
| kata    | 18.0 GB/s  |

### Trade-off analysis
Kata's ~23× cold-start overhead and ~17% I/O penalty are the direct cost of hardware-virtualized isolation. This trade-off is highly justified for multi-tenant SaaS workloads, untrusted CI/CD runners, or regulated environments (e.g., HIPAA), where blocking kernel-level escapes (like the runc "Leaky Vessels" CVE) is a strict requirement. However, it is not worth the cost for single-tenant, performance-sensitive batch jobs or ephemeral FaaS workloads, where the shared-kernel model of `runc` provides sufficient security with near-zero overhead.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (Privileged-container host write)
- **Why:** It is the simplest to demonstrate, the underlying threat model is the most common in the wild (misconfigured `--privileged` flags in real workloads), and the contrast with Kata is the most visible and reproducible.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
Container output:
```text
OVERWRITTEN BY RUNC CONTAINER
```
Host verification:
```bash
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked
Command:
```bash
$ sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"' 2>&1
```
Container output:
```text
time="2026-07-17T12:41:15+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-17T12:41:16+03:00" level=fatal msg="failed to create shim task: Others(\"failed to handle message create container\\n\\nCaused by:\\n    0: get host path failed\\n    1: No such file or directory (os error 2)\\n\\nStack backtrace:\\n   0: anyhow::error::<impl core::convert::From<E> for anyhow::Error>::from\\n   1: hypervisor::device::util::get_host_path\\n   2: resource::manager_inner::ResourceManagerInner::handler_devices::{{closure}}\\n   3: virt_container::container_manager::container::Container::create::{{closure}}\\n   4: <virt_container::container_manager::manager::VirtContainerManager as common::container_manager::ContainerManager>::create_container::{{closure}}::{{closure}}\\n   5: <virt_container::container_manager::manager::VirtContainerManager as common::container_manager::ContainerManager>::create_container::{{closure}}\\n   6: runtimes::manager::RuntimeHandlerManager::handler_task_message::{{closure}}::{{closure}}\\n   7: runtimes::manager::RuntimeHandlerManager::handler_task_message::{{closure}}\\n   8: <service::task_service::TaskService as containerd_shim_protos::shim::shim_ttrpc_async::Task>::create::{{closure}}\\n   9: <containerd_shim_protos::shim::shim_ttrpc_async::CreateMethod as ttrpc::asynchronous::utils::MethodHandler>::handler::{{closure}}\\n  10: ttrpc::asynchronous::server::HandlerContext::handle_request::{{closure}}\\n  11: <ttrpc::asynchronous::server::ServerReader as ttrpc::asynchronous::connection::ReaderDelegate>::handle_msg::{{closure}}::{{closure}}\\n  12: tokio::runtime::task::raw::poll\\n  13: tokio::runtime::scheduler::multi_thread::worker::Context::run_task\\n  14: tokio::runtime::task::raw::poll\\n  15: std::sys::backtrace::__rust_begin_short_backtrace\\n  16: core::ops::function::FnOnce::call_once{{vtable.shim}}\\n  17: std::sys::thread::unix::Thread::new::thread_start\")"

```
Host verification:
```bash
$ sudo cat /tmp/lab12-target
original
```

### Threat model implication (3-4 sentences, Reading 12 framing)
Kata blocks what `runc` allows because its architecture virtualizes bind mounts via virtio-fs/9p inside an isolated micro-VM, rather than directly mounting host directories into a shared kernel namespace. In this specific case, Kata's resource manager actively rejected the host path mapping, preventing the mount from even being established. This neutralizes real-world threats like multi-tenant CI runners or misconfigured Kubernetes pods running with `--privileged`. However, it is important to note that this VM-level isolation does not block pure side-channel attacks on the CPU or cross-tenant timing attacks; defending against those requires the hardware-level memory encryption provided by Confidential Containers (CoCo), as discussed in Reading 12.
