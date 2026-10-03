# Lab 12 — VM-Backed Container Isolation with Kata

![difficulty](https://img.shields.io/badge/difficulty-advanced-red)
![topic](https://img.shields.io/badge/topic-VM%20Sandboxing-blue)
![points](https://img.shields.io/badge/points-10-orange)
![tech](https://img.shields.io/badge/tech-Kata%20%2B%20containerd-informational)

> **Goal:** Run the same container on `runc` and on Kata, measure what the extra kernel costs you and what it buys you, then show an escape that works on one and not the other.
> **Deliverable:** A PR from `feature/lab12` with `submissions/lab12.md`. Submit the PR link via Moodle.
> **Bonus lab:** 4 + 4 + 2 points. Reading 12 covers the theory.

## Setup

This lab changes the machine it runs on. Read this section before you start.

- A **Linux host with `/dev/kvm`**, containerd and `nerdctl`. `ls -l /dev/kvm` must succeed. WSL2 has it; Docker Desktop's VM does not expose it, and neither do most cloud instances unless you asked for nested virtualisation.
- `sudo`. The installer writes to `/opt/kata` and edits `/etc/containerd/config.toml`.
- Do this on a machine you are willing to reconfigure, or a throwaway VM. Not your only laptop the night before a deadline.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab12
mkdir -p labs/lab12/results
```

```bash
ls -l /dev/kvm && command -v containerd nerdctl
```

Provided in `labs/lab12/`: `scripts/install-kata-assets.sh` (downloads and unpacks the pinned Kata static build), `scripts/configure-containerd-kata.sh` (registers the runtime with containerd) and `setup/build-kata-runtime.sh` (an optional from-source build). Read all three before running any of them with `sudo`.

## Task 1 — Two runtimes, one image (4 pts)

### 12.1 Install Kata

<!-- verify:skip installs to /opt and edits containerd's config on the host -->
```bash
sudo bash labs/lab12/scripts/install-kata-assets.sh
sudo bash labs/lab12/scripts/configure-containerd-kata.sh
cat /opt/kata/VERSION
grep -A2 'runtimes.kata' /etc/containerd/config.toml
```

The installer pins Kata 4.1.0. Pass a version as an argument to override it, and record which you used: benchmark numbers from different runtimes are not comparable.

### 12.2 The same command, twice

<!-- verify:skip requires the kata runtime from 12.1 -->
```bash
sudo nerdctl run --rm alpine:3.20 uname -r \
  | tee labs/lab12/results/runc-kernel.txt
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 uname -r \
  | tee labs/lab12/results/kata-kernel.txt

sudo nerdctl run --rm alpine:3.20 ls /dev | wc -l
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 ls /dev | wc -l

sudo nerdctl run --rm alpine:3.20 sh -c 'grep ^CapEff /proc/1/status'
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c 'grep ^CapEff /proc/1/status'
```

**Submit** in `submissions/lab12.md`, section `## Task 1`:

- Both kernel versions, and the host's. One of them will not match the host.
- The device counts and the capability masks, side by side.
- Three or four sentences: a container on `runc` reports the host's kernel release. Explain what that single line of output tells an attacker who has just landed in your container, and what changes when the answer is a different kernel.

## Task 2 — What the isolation costs (4 pts)

### 12.3 Measure, do not guess

<!-- verify:skip requires the kata runtime from 12.1 -->
```bash
for rt in runc kata; do
  [ "$rt" = kata ] && FLAG="--runtime=io.containerd.kata.v2" || FLAG=""
  echo "== $rt startup =="
  # One warm-up that is thrown away, then five timed runs
  sudo nerdctl run --rm $FLAG alpine:3.20 true >/dev/null 2>&1
  for i in 1 2 3 4 5; do
    /usr/bin/time -f '%e' sudo nerdctl run --rm $FLAG alpine:3.20 true 2>&1 | tail -1
  done
done | tee labs/lab12/results/startup.txt

for rt in runc kata; do
  [ "$rt" = kata ] && FLAG="--runtime=io.containerd.kata.v2" || FLAG=""
  echo "== $rt io =="
  # Write to the container's filesystem, not /dev/null: the point is to cross
  # the storage layer, which is where a VM-backed runtime differs from runc
  sudo nerdctl run --rm $FLAG alpine:3.20 \
    sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1 | tail -1'
done | tee labs/lab12/results/io.txt
```

**Submit**, section `## Task 2`:

- Five startup times per runtime after the warm-up, with the median for each. Report the median, not the mean: one slow run skews an average.
- The I/O throughput figures, and one sentence on why the benchmark writes to a file rather than to `/dev/null`.
- Memory overhead per container, and how you measured it.
- A table of three workloads from your own experience or the reading, each with a verdict: `runc`, Kata, or "needs more information", and one sentence of justification each.
- Three or four sentences: your startup numbers differ by roughly an order of magnitude. For which class of workload does that number not matter at all, and why?

## Bonus — An escape that Kata stops (2 pts)

Reading 12 argues that a second kernel contains what namespaces do not. Show it.

### 12.4 Pick a vector

The simplest convincing one is a privileged container with a host bind mount. It is not a CVE: it is the misconfiguration that appears in real clusters, and the contrast with Kata is visible in one command.

Verified on `runc` while writing this lab: an unprivileged Alpine container sees 15 entries in `/dev` and a capability mask of `00000000a80425fb`; with `--privileged` it sees 181 entries and `000001ffffffffff`, and writing through a `-v /tmp:/host_tmp` mount changes the file on the host.

<!-- verify:skip writes to the host filesystem on purpose -->
```bash
echo original | sudo tee /tmp/lab12-target
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
cat /tmp/lab12-target
```

### 12.5 Now on Kata

```bash
# YOUR TASK: run the same escape against the kata runtime and record what happens
# Requirements:
#   - the identical command, with --runtime=io.containerd.kata.v2 added
#   - capture the outcome, whatever it is, including if it partly works
# Hints:
#   - think about what a bind mount means when the container has its own kernel
#   - --privileged inside a VM grants privileges over which kernel?
```

**Submit**, section `## Bonus`:

- Both runs and the state of the host file after each.
- The device count and capability mask for a privileged container under each runtime.
- Three or four sentences: explain the result in terms of what `--privileged` actually grants and to what. If the escape partly worked on Kata, say so and explain which part.
- One sentence on the honest limit: name something Kata does not protect you from.

## Acceptance criteria

- Task 1 (4): both kernel versions with the host's for comparison; device counts and capability masks side by side; the what-an-attacker-learns answer is about the specific output, not general theory.
- Task 2 (4): five timings per runtime with medians; I/O figures; a memory measurement with its method; three workloads judged with reasons; the order-of-magnitude answer names a workload class where it does not matter.
- Bonus (2): both runs recorded with the host file's state; masks and device counts for both; an explanation in terms of what `--privileged` grants; one honest limitation of Kata.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab12.md> (submissions/lab12.md, ...)
git commit -m "feat(lab12): kata vs runc isolation, cost and escape"
git push -u origin feature/lab12
```

Undo the host changes when you are done: remove the `kata` runtime block from `/etc/containerd/config.toml`, restart containerd, and delete `/opt/kata`.


## Common pitfalls

- No `/dev/kvm`, no Kata. Check first: the failure otherwise arrives several minutes into an install.
- Kata is a containerd runtime, so `docker run --runtime=` will not reach it. Use `nerdctl`, or `ctr`, or Kubernetes with a RuntimeClass.
- `configure-containerd-kata.sh` edits `/etc/containerd/config.toml`. Keep a copy: an invalid config leaves containerd refusing to start, which takes every container on the host with it.
- The first Kata start is slow because the guest kernel and image are cold, which is why the loop above throws one run away before timing five.
- Timing with `time` includes `nerdctl` and containerd overhead, identically for both runtimes, which is why the comparison is still fair. Say so in your report rather than pretending you measured the runtime alone.
- The installer used to resolve "latest", so two students could benchmark different Kata versions and compare numbers that were never comparable. It is pinned now; if you override it, say which version you used.

## Resources

- [Kata Containers documentation](https://katacontainers.io/docs/) and the [installation guides](https://github.com/kata-containers/kata-containers/tree/main/docs/install)
- [containerd runtime configuration](https://github.com/containerd/containerd/blob/main/docs/cri/config.md)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/) — how this is selected in a cluster rather than per command
- [gVisor](https://gvisor.dev/docs/) — the other approach to the same problem, worth contrasting in Task 2
