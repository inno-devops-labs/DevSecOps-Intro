# Lab 12 — Kata Containers: VM-backed Container Sandboxing

## Task 1 — Install and Configure Kata

### Environment and setup evidence

I installed and configured the required container runtime components for Lab 12.

Containerd version:

```text
containerd github.com/containerd/containerd/v2 2.2.1
```

Nerdctl version:

nerdctl version 2.2.0

Kata shim evidence:

/usr/local/bin/containerd-shim-kata-v2
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.30.0, commit: 5540f50198140c444aa8eeac8ee17208bdd4bab7

The Kata static assets were installed using the provided lab script, and containerd was configured with the io.containerd.kata.v2 runtime.

### Virtualization limitation

The VM environment does not expose hardware virtualization to the Linux guest:

=== virtualization flags ===
0

=== /dev/kvm ===
ls: cannot access '/dev/kvm': No such file or directory

This means the guest OS cannot access KVM. Since Kata Containers requires a hardware virtualization backend to create its VM-backed sandbox, the Kata runtime could be installed and configured, but Kata containers could not be started successfully in this VirtualBox environment.

Kata runtime test result:

time="2026-05-13T15:40:59+03:00" level=fatal msg="failed to create shim task: Could not create the sandbox resource controller failed to add any hypervisor device to devices cgroup"

## Task 2 — Run and Compare Containers

### runc baseline

I successfully started OWASP Juice Shop using the default runc/containerd path and verified that the application was reachable.

Health check:

juice-runc: HTTP 200

HTTP header check:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: text/html; charset=UTF-8

### Kata runtime attempt

The same environment was prepared for Kata using io.containerd.kata.v2, but Kata execution failed because /dev/kvm is not available inside the VM.

Expected Kata behavior in a working environment:

runc containers share the host kernel.
Kata containers run inside a lightweight VM with a separate guest kernel.
Kata provides a stronger isolation boundary because a container escape must also break out of the guest VM.

Observed result in this environment:

runc worked successfully.
Kata was installed and configured.
Kata could not start because the host VM does not expose hardware virtualization.

## Task 3 — Isolation Tests

Because Kata containers could not start without /dev/kvm, runtime isolation tests such as guest dmesg, /proc, network interfaces, and kernel module comparison could not be completed live.

The key isolation finding is still clear from the diagnostics:

egrep -c '(vmx|svm)' /proc/cpuinfo = 0
/dev/kvm = missing

This prevents Kata from launching the VM sandbox.

Isolation implications

runc:

Uses Linux namespaces and cgroups.
Shares the host kernel with the container.
A kernel-level container escape could directly impact the host.

Kata:

Runs the container inside a lightweight virtual machine.
Uses a separate guest kernel.
Adds a VM boundary between the workload and the host.
A container escape would first land inside the guest VM, not directly on the host.

## Task 4 — Performance Summary

A full Kata startup and latency comparison could not be completed because the Kata runtime cannot launch without KVM.

Expected performance trade-offs:

runc has lower startup overhead and is better for high-density workloads.
Kata has higher startup overhead because it must create a lightweight VM.
Kata provides stronger isolation and is better suited for untrusted workloads, multi-tenant environments, CI sandboxes, and workloads where stronger tenant separation is more important than startup speed.
Recommendation

For normal trusted application workloads, runc is simpler, faster, and operationally lighter.

For untrusted or multi-tenant workloads, Kata is preferred because it adds a VM-backed isolation boundary. However, Kata requires hardware virtualization support. In this lab environment, VirtualBox did not expose VT-x/AMD-V to the guest, so /dev/kvm was unavailable and Kata could not launch containers.

Files produced
labs/lab12/setup/containerd-version.txt
labs/lab12/setup/nerdctl-version.txt
labs/lab12/setup/kata-built-version.txt
labs/lab12/setup/kata-diagnostics.txt
labs/lab12/kata/test-run.txt
labs/lab12/runc/health.txt

