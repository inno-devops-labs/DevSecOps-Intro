# Lab 12 — BONUS — Kata Containers: Isolation, Performance, and a Real Escape PoC

![difficulty](https://img.shields.io/badge/difficulty-advanced-red)
![topic](https://img.shields.io/badge/topic-VM%20Sandboxing-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Kata%20Containers-informational)

> **Goal:** Install Kata as a containerd runtime, run the same workload on `runc` and `kata` to compare kernel isolation + performance overhead, then (bonus) demonstrate a real container-escape PoC succeeds on `runc` and fails on `kata` — the headline value-prop made concrete.
> **Deliverable:** A PR from `feature/lab12` with `submissions/lab12.md` + benchmark outputs. Submit PR link via Moodle.

> 🌟 **This is a BONUS lab** — 10 pts total (Task 1: 4 + Task 2: 4 + Bonus: 2).
> Bonus labs count toward a separate **20% weight** in your final grade (see README).
> Difficulty is **advanced** — kernel/runtime layer; requires Linux host with KVM access.

---

## Overview

In this lab you will practice:
- **Kata Containers v3.x** — VM-backed container runtime under containerd (Reading 12)
- **Side-by-side runtime comparison** — runc vs kata, observable differences in kernel + devices + perf
- **Performance benchmark** — startup time + CPU-bound + I/O-bound, with real numbers
- (Bonus) **Container-escape PoC demonstration** — a real escape that succeeds on runc, fails on Kata

> **Read Reading 12 first.** It covers the whole landscape (Kata, gVisor, Firecracker, Confidential Containers) — this lab focuses on Kata, but the reading sets context.

---

## Project State

**You should have from Labs 1, 7:**
- Familiarity with containers + Pod Security Standards (Lab 7)
- A Linux host with kernel ≥ 5.8 + KVM access (`/dev/kvm` exists + readable)

**This lab adds:**
- Kata Containers installed + registered as a containerd runtime
- Side-by-side run-comparison data (runc vs kata)
- Performance + isolation analysis with real numbers
- (Bonus) Hands-on demonstration of an escape blocked by VM isolation

> ⚠️ **macOS / Windows users:** Kata requires KVM, which doesn't work in Docker Desktop's Linux VM by default. Either spin up a Linux VM with nested virtualization, use a KVM-enabled cloud VM, or use a bare-metal Linux machine. See Reading 12 for context.

---

## Setup

You need:
- **Linux host with KVM** — `lsmod | grep kvm` shows kvm_intel or kvm_amd
- **`/dev/kvm` readable** — add yourself to `kvm` group if needed
- **containerd + nerdctl** installed (most Linux distros via packages)
- **`sudo`** — install Kata into `/opt`, modify `/etc/containerd/config.toml`

```bash
git switch main && git pull
git switch -c feature/lab12

lsmod | grep -E "kvm_intel|kvm_amd" && ls -la /dev/kvm
sudo systemctl status containerd
nerdctl --version

mkdir -p labs/lab12/results
```

> **Plumbing provided** (in `labs/lab12/`):
> - [`labs/lab12/scripts/install-kata-assets.sh`](lab12/scripts/install-kata-assets.sh) — downloads kata-static + configures
> - [`labs/lab12/scripts/configure-containerd-kata.sh`](lab12/scripts/configure-containerd-kata.sh) — updates containerd config to register `kata` runtime
> - [`labs/lab12/setup/build-kata-runtime.sh`](lab12/setup/build-kata-runtime.sh) — optional from-source build

---

## Task 1 — Install + Hello-World on Both Runtimes (4 pts)

**Objective:** Install Kata, register it with containerd, run the same image under both runtimes, confirm the kernel inside the container differs.

### 12.1: Install Kata

```bash
sudo bash labs/lab12/scripts/install-kata-assets.sh
sudo bash labs/lab12/scripts/configure-containerd-kata.sh
sudo systemctl restart containerd

# Verify the registration
grep -A 2 'runtimes.kata' /etc/containerd/config.toml
# Should show:
# [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
#   runtime_type = 'io.containerd.kata.v2'

cat /opt/kata/VERSION
# Should print 3.x.x
```

### 12.2: Hello-world on both runtimes

```bash
# runc (default)
sudo nerdctl run --rm alpine:3.20 sh -c "uname -a; head -3 /proc/cpuinfo" \
  > labs/lab12/results/runc-kernel.txt 2>&1
cat labs/lab12/results/runc-kernel.txt

# kata
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c "uname -a; head -3 /proc/cpuinfo" \
  > labs/lab12/results/kata-kernel.txt 2>&1
cat labs/lab12/results/kata-kernel.txt
```

### 12.3: Document in `submissions/lab12.md`

````markdown
# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): <uname -a>
- KVM accessible: <ls -la /dev/kvm>
- containerd version: <containerd --version>

### Kata installation
- Kata version: <cat /opt/kata/VERSION>
- containerd config snippet:
```toml
<paste the runtimes.kata block>
```

### Kernel inside containers
**runc:**
```
<paste runc-kernel.txt — should show host kernel>
```

**kata:**
```
<paste kata-kernel.txt — should show DIFFERENT kernel (Kata's mini-VM kernel)>
```

### Why the kernel differs (Reading 12)
Reading 12 explains the model. Reference Lecture 7 slide 14 — runc CVE-2024-21626 ("Leaky Vessels").
What does the kernel difference imply for that attack class? (2-3 sentences.)
````

---

## Task 2 — Isolation + Performance Benchmark (4 pts)

> ⏭️ Optional. Skipping won't break Task 1 or the bonus.

**Objective:** Quantify two trade-offs — Kata's isolation gain, Kata's performance cost — with real numbers.

### 12.4: Isolation test

```bash
# /dev contents
sudo nerdctl run --rm alpine:3.20 ls /dev > labs/lab12/results/runc-devs.txt
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 ls /dev \
  > labs/lab12/results/kata-devs.txt
diff labs/lab12/results/runc-devs.txt labs/lab12/results/kata-devs.txt \
  > labs/lab12/results/dev-diff.txt || true

# Capability set (sometimes the more visible isolation)
sudo nerdctl run --rm alpine:3.20 sh -c "grep ^Cap /proc/1/status" \
  > labs/lab12/results/runc-caps.txt
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c "grep ^Cap /proc/1/status" \
  > labs/lab12/results/kata-caps.txt
```

### 12.5: Performance benchmark

```bash
# Cold start (avg of 5 runs)
for runtime in runc kata; do
  RUNTIME_FLAG=""
  [ "$runtime" = "kata" ] && RUNTIME_FLAG="--runtime=io.containerd.kata.v2"
  echo "=== $runtime ==="
  for i in 1 2 3 4 5; do
    START=$(date +%s.%N)
    sudo nerdctl run --rm $RUNTIME_FLAG alpine:3.20 echo "hello" > /dev/null
    END=$(date +%s.%N)
    echo "$i: $(echo "$END - $START" | bc) s"
  done
done | tee labs/lab12/results/startup-bench.txt

# I/O-bound: 100MB dd through /dev/null
for runtime in runc kata; do
  RUNTIME_FLAG=""
  [ "$runtime" = "kata" ] && RUNTIME_FLAG="--runtime=io.containerd.kata.v2"
  echo "=== $runtime I/O ==="
  sudo nerdctl run --rm $RUNTIME_FLAG alpine:3.20 \
    sh -c 'dd if=/dev/zero of=/dev/null bs=1M count=100 2>&1' | grep "copied"
done | tee labs/lab12/results/io-bench.txt
```

### 12.6: Document in `submissions/lab12.md`

````markdown
## Task 2: Isolation + Performance

### Isolation: /dev diff
```
<paste dev-diff.txt — list specific differences>
```

### Isolation: capability sets
runc:
```
<paste runc-caps.txt>
```
kata:
```
<paste kata-caps.txt>
```

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | <e.g. 0.45> |
| kata | <e.g. 2.10> |

**Overhead: ~<X>× cold start (expected ~5× per Reading 12 table)**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | <e.g. 12.5 GB/s> |
| kata | <e.g. 1.2 GB/s> |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
When is the security gain (separate kernel, runc-CVE class blocked) worth the cost?
When isn't it? Give one example each (e.g., "multi-tenant SaaS workloads = yes;
single-tenant batch jobs = no").
````

---

## Bonus Task — Real Container-Escape PoC: runc vs Kata (2 pts)

> 🌟 **The headline value proposition.** Reading 12 + Lecture 7 made the case that VM-backed isolation defeats container-escape CVEs. This bonus DEMONSTRATES it: take a real, public, well-understood escape PoC; show it works on runc; show it doesn't work on Kata. **Reproducible evidence of the trade-off you analyzed in Task 2.**

**Objective:** Pick **one** escape vector. Demonstrate it succeeds on runc + fails on Kata. Document why.

### B.1: Pick your escape vector

Three good options (varying difficulty):

| Vector | Difficulty | Description |
|--------|------------|-------------|
| **A. CVE-2019-5736 runc PoC** | ★★★ | The classic; PoC by `Frichetten/CVE-2019-5736-PoC` on GitHub. Overwrites the host's `runc` binary from inside a container. Patched in runc ≥ 1.0.0-rc6. To demonstrate, you need a deliberately old runc on a sandboxed VM. |
| **B. Privileged-container host write** | ★ | Run `nerdctl run --privileged -v /:/host alpine ...`. From inside, `echo "hacked" >> /host/etc/HOSTED` writes to the host filesystem. Trivial to demonstrate; the "escape" is the privileged flag itself. **Easier and convincing for this bonus.** |
| **C. cgroup v1 release_agent escape (CVE-2022-0492)** | ★★ | Mount cgroupfs inside container, write a `release_agent` script that runs on the host. Patched on cgroup v2; old kernels still vulnerable. Best on a cgroup v1 sandbox VM. |

> **Recommended for this lab: vector B** (privileged-container host write). It's the simplest to demonstrate, the underlying threat model is the most common (misconfigured `--privileged` in real workloads), and the contrast with Kata is the most visible. Vectors A and C are more "real CVE" but harder to set up reproducibly.

### B.2: Demonstrate on runc

```bash
# Sandbox host file we'll try to overwrite
sudo touch /tmp/lab12-target
sudo chown root:root /tmp/lab12-target
echo "original" | sudo tee /tmp/lab12-target

# runc with --privileged + host bind mount: the escape
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'

# Verify on host
sudo cat /tmp/lab12-target
# Should print: OVERWRITTEN BY RUNC CONTAINER
```

### B.3: Demonstrate Kata blocks it

```bash
# Reset target
echo "original" | sudo tee /tmp/lab12-target

# Same flags, kata runtime
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"' 2>&1 \
  | tee labs/lab12/results/kata-escape-attempt.txt

# Verify on host — Kata's bind mount is INSIDE the micro-VM; host file is untouched
sudo cat /tmp/lab12-target
# Should still print: original
```

### B.4: Document in `submissions/lab12.md`

````markdown
## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** <A / B / C>
- **Why:** <1-2 sentences>

### runc: escape succeeds
Command:
```bash
<paste your runc command>
```

Container output:
```
<paste — should show the write succeeded>
```

Host verification:
```
<sudo cat /tmp/lab12-target — should show OVERWRITTEN BY RUNC CONTAINER>
```

### Kata: escape blocked
Command:
```bash
<paste your kata command>
```

Container output:
```
<paste kata-escape-attempt.txt — should show the write went to the MICRO-VM filesystem, not the host>
```

Host verification:
```
<sudo cat /tmp/lab12-target — should still show "original">
```

### Threat model implication (3-4 sentences, Reading 12 framing)
- Why does Kata block what runc allows? (Reference: Kata's micro-VM filesystem IS NOT the host filesystem — bind mounts are virtualized via virtio-fs/9p inside the VM.)
- What real-world threat does this map to? (Multi-tenant CI runners running `--privileged` containers; misconfigured Kubernetes pods.)
- What does this NOT block? (Pure side-channel attacks on the kernel itself, cross-tenant timing attacks. Reading 12's "Confidential Containers" section is where THOSE get defenses.)
````

---

## Cleanup

```bash
sudo nerdctl ps -a --filter ancestor=alpine:3.20 -q | xargs -r sudo nerdctl rm -f
sudo rm -f /tmp/lab12-target
```

---

## How to Submit

```bash
git add submissions/lab12.md
git commit -m "feat(lab12): kata vs runc isolation + perf + escape PoC"
git push -u origin feature/lab12
```

PR checklist body:

```text
- [x] Task 1 — Kata installed; both runtimes run; kernel diff documented
- [ ] Task 2 — Isolation + 5-run startup + I/O benchmark with trade-off analysis
- [ ] Bonus — Escape PoC succeeds on runc, fails on Kata (with host-side verification)
```

---

## Acceptance Criteria

### Task 1 (4 pts)
- ✅ Kata installed; `cat /opt/kata/VERSION` returns 3.x
- ✅ containerd config includes the `runtimes.kata` block
- ✅ Both runtimes run hello-world successfully
- ✅ Kernel inside containers documented for BOTH runtimes; diff visible
- ✅ "Why the kernel differs" answer correctly maps to Reading 12 + runc CVE class

### Task 2 (4 pts)
- ✅ /dev diff documented (isolation evidence)
- ✅ Capability set diff documented
- ✅ Startup time measured for both (5 runs averaged)
- ✅ I/O benchmark captured for both
- ✅ Trade-off analysis has both "would deploy" and "wouldn't deploy" scenarios

### Bonus Task (2 pts)
- ✅ Escape vector picked + justified (1-2 sentences)
- ✅ runc demonstration: container modifies host filesystem (verified from outside the container)
- ✅ Kata demonstration: same command, host file UNCHANGED (verified from outside)
- ✅ Threat-model implication answer references the micro-VM filesystem model + a real-world multi-tenant case
- ✅ Honest note about what Kata DOES NOT block (kernel side-channels, cross-tenant timing)

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Install + hello-world | **4** | Kata working + both runtimes + kernel-diff with Reading-12 explanation |
| **Task 2** — Isolation + perf | **4** | /dev + caps diff + 5-run startup + I/O bench + production-trade-off analysis |
| **Bonus Task** — Escape PoC | **2** | runc succeeds + kata fails + host-side verification + threat-model + honest limits |
| **Total** | **10** | Task 1 + Task 2 + Bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Reading 12](../lectures/reading12.md) — the deep-dive companion (Kata + gVisor + Firecracker + CoCo)
- [Kata Containers documentation](https://katacontainers.io/docs/) — install + ops
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md) — how the VM-per-container model works
- [CVE-2019-5736 (runc escape) writeup](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html) — for vector A
- [CVE-2022-0492 (cgroup v1 release_agent)](https://www.crowdstrike.com/blog/cgroup-v1-release-agent-vulnerability/) — for vector C
- [Linux KVM documentation](https://www.kernel.org/doc/html/latest/virt/kvm/index.html) — the hypervisor Kata uses

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`ls /dev/kvm: No such file or directory`** — you're not on a KVM-capable host. Bare-metal Linux works; Docker Desktop's Linux VM doesn't by default; cloud VMs vary (most enable KVM; older `t2.micro`-style EC2s do not).
- 🚨 **`Permission denied on /dev/kvm`** — `sudo usermod -aG kvm $USER && newgrp kvm`, OR run nerdctl with `sudo`.
- 🚨 **Kata container starts but takes 60-90s** — Kata's nested networking + microVM boot add latency. Don't conclude "Kata is broken"; wait.
- 🚨 **`nerdctl run --runtime=...` fails with "no such runtime"** — `sudo systemctl restart containerd` after editing the config.
- 🚨 **dd reports MB/s on runc but B/s on kata** — different output formats due to dd timing. Use `| grep "copied"` to extract the rate line consistently.
- 🚨 **Benchmark numbers vary wildly between runs** — KVM startup is unstable for the first few. Discard the first 1-2 runs.
- 🚨 **Bonus (vector B): `--privileged + -v /:/host` on Kata writes "succeed"** but on the **micro-VM**, NOT the host. The verify-from-outside step is what makes the bonus convincing. Always cat the file from a separate shell on the HOST.
- 💡 **If the lab is impossible on your laptop**: spin up a cloud VM ($1-2 for a few hours). c6i.xlarge on AWS, n2-standard-4 on GCP — both support KVM.

</details>

<details>
<summary>🪜 Looking outside this course</summary>

- **gVisor** (Reading 12) — alternative user-space syscall interception; lower cold-start, weaker syscall compatibility
- **Firecracker** — AWS's minimal VMM; ~125ms boot; powers Lambda + Fargate
- **Confidential Containers (CoCo)** — protects container memory from the HOST (Intel TDX / AMD SEV-SNP); 2026 frontier
- **In your portfolio:** "I evaluated Kata Containers vs runc for sandboxed workloads, measured 5× cold-start overhead vs near-zero CPU overhead, and demonstrated a real container-escape blocked by VM isolation" is a strong DevSecOps interview line.

</details>
