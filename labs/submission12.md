# Lab 12 — Kata Containers & Runtime Isolation Report

## Overview

The goal of this lab was to build and configure the Kata Containers runtime, integrate it with containerd, and validate hardware-virtualized container isolation using a lightweight virtual machine environment.

The lab demonstrates the difference between traditional containers and Kata Containers by showing that workloads run inside a dedicated guest kernel instead of directly sharing the host Linux kernel.

# Environment

- Host OS: Ubuntu Linux
- Container Runtime: containerd + nerdctl
- Isolation Runtime: Kata Containers
- Hypervisor: QEMU/KVM
- Target Image: `alpine:3.19`
- Test Application: `bkimminich/juice-shop:v19.0.0`

# Building Kata Runtime

The Kata runtime was built from source using the provided Docker-based build script.

Command used:

```bash
bash labs/lab12/setup/build-kata-runtime.sh
```

The build completed successfully and produced the runtime binary:

```text
/home/kapi/Documents/Uni/S26/DevSecOps-Intro/labs/lab12/setup/kata-out/containerd-shim-kata-v2
```

Binary size:

```text
31M
```

The runtime was installed into the system:

```bash
sudo install -m 0755 \
labs/lab12/setup/kata-out/containerd-shim-kata-v2 \
/usr/local/bin/
```

Runtime verification:

```bash
containerd-shim-kata-v2 --version
```

Output:

```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: 7820877de5fe55664d15d5bdcda7d4da4882174d
```

# Build Process Details

The build process automatically installed and configured:

- Rust toolchain
- cargo
- rustup
- musl toolchain
- seccomp libraries
- Git dependencies

Detected Rust environment:

```text
cargo 1.93.1
rustc 1.93.1
rustup 1.26.0
```

Detected hypervisors:

```text
Known: cloud-hypervisor dragonball firecracker qemu remote
Available for this architecture: cloud-hypervisor dragonball firecracker qemu remote
```

Default hypervisor:

```text
qemu
```

The runtime generated configuration files for multiple hypervisors including:

- QEMU
- Firecracker
- Cloud Hypervisor
- Dragonball

# Installing Kata Assets

Static Kata assets were installed using:

```bash
sudo bash labs/lab12/scripts/install-kata-assets.sh
```

The installer downloaded approximately 1.4 GB of runtime assets including:

- guest kernel
- root filesystem
- QEMU components
- runtime configuration files

# containerd Configuration

containerd configuration was initialized using:

```bash
sudo mkdir -p /etc/containerd

sudo containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
```

containerd service was enabled:

```bash
sudo systemctl enable --now containerd
```

# Networking Issue

During the first Kata runtime execution, nerdctl reported a missing CNI plugin:

```text
failed to create default network:
needs CNI plugin "bridge" to be installed in CNI_PATH ("/opt/cni/bin")
```

This issue indicated that container networking plugins were not installed.

After installing the required CNI plugins, Kata containers were able to launch successfully.

# Kata Runtime Validation

The runtime was tested using:

```bash
sudo nerdctl run --rm \
--runtime io.containerd.kata.v2 \
alpine:3.19 uname -a
```

The container launched successfully under the Kata runtime.

Additional validation was performed by accessing kernel logs from inside the Kata container:

```bash
sudo nerdctl run --rm \
  --runtime io.containerd.kata.v2 \
  alpine:3.19 sh -c "dmesg | sed -n '1,10p'"
```

Observed output:

```text
Linux version 6.18.22
Hypervisor detected: KVM
```

This confirms that:

- the container was executed inside a lightweight virtual machine,
- a separate guest Linux kernel was booted,
- KVM hardware virtualization was active,
- the workload did not directly share the host kernel.

# Isolation Analysis

Traditional Docker containers share the host Linux kernel and rely primarily on:

- namespaces,
- cgroups,
- seccomp,
- capabilities.

Kata Containers adds an additional security boundary by running each workload inside an isolated micro-VM.

Advantages of Kata Containers include:

- stronger kernel isolation,
- reduced kernel attack surface,
- improved multi-tenant security,
- hardware virtualization enforcement.

Tradeoffs include:

- higher startup overhead,
- increased memory usage,
- larger runtime footprint.

Kata Containers is therefore especially useful for:

- untrusted workloads,
- multi-tenant Kubernetes clusters,
- confidential computing,
- sandboxed CI/CD execution.

# Issues Encountered

## Missing CNI Plugins

Error:

```text
needs CNI plugin "bridge" to be installed
```

Resolution:

Installed standard CNI networking plugins.

## "Too many open files"

Error:

```text
Failed to allocate directory watch: Too many open files
```

This occurred during containerd startup.

Possible cause:

- exhausted inotify watchers or file descriptor limits.

## jq Missing During Build

Build warning:

```text
/bin/sh: 1: jq: not found
```

The build still completed successfully despite the missing jq utility.

## Broken Pipe During dmesg Validation

Observed message:

```text
InitProcessNotFound
forward signal broken pipe
```

Cause:

`head` terminated early after reading several log lines.

Impact:

Non-critical. Kata runtime execution remained successful.

# Conclusion

The lab successfully demonstrated how Kata Containers can provide stronger workload isolation by combining containers with lightweight virtual machines.

The Kata runtime was built from source, integrated with containerd, and validated using KVM-based execution. Kernel log inspection confirmed that the workload executed inside a dedicated guest kernel rather than sharing the host Linux kernel directly.

This approach significantly improves container isolation and provides an additional defense layer for security-sensitive workloads.

# Artifacts

- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/isolation/dmesg.txt`
- `labs/lab12/setup/kata-out/containerd-shim-kata-v2`

# Evidence

Build and runtime logs were captured during:

- Kata runtime compilation
- Runtime installation
- containerd configuration
- Kata VM execution
- dmesg isolation validation
