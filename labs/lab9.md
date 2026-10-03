# Lab 9 — Runtime Detection and Policy as Code

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Runtime%20%2B%20PaC-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Falco%20%2B%20Conftest-informational)

> **Goal:** Watch a container from the kernel's point of view with Falco, write a rule that catches something the defaults miss, and enforce the same class of rule before deployment with Conftest.
> **Deliverable:** A PR from `feature/lab9` with `submissions/lab9.md`, your Falco rules and your Rego policy. Submit the PR link via Moodle.
> **Builds on:** the hardening from Lab 7. **Used by:** Lab 10 imports these findings.

## Setup

- Docker on a Linux kernel with eBPF. WSL2 works. On macOS use Colima with `--vm-type vz` or a Linux VM: Docker Desktop's VM does not expose the host kernel.
- `conftest` 0.69.x.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab9
```

```bash
docker --version && conftest --version
mkdir -p labs/lab9/falco/rules labs/lab9/falco/logs
```

Provided: `labs/lab9/manifests/` holds a hardened and an unhardened Kubernetes deployment plus a Compose file, and `labs/lab9/policies/` holds the Rego your Task 2 policy joins.

## Task 1 — Runtime detection with Falco (6 pts)

### 9.1 Start Falco and a target

```bash
docker run -d --name falco --privileged \
  -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.1 \
  falco -U -o json_output=true -o time_format_iso_8601=true

docker run -d --name lab9-target alpine:3.20 sleep 1d
sleep 10
docker logs falco 2>&1 | tail -3
```

On kernels missing some tracepoints, WSL2 included, Falco prints `failure while attaching TOCTOU mitigation program`. Detection still works; the container should be `running`.

### 9.2 Make it notice you

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
docker exec lab9-target sh -c 'cat /etc/shadow'
sleep 8
docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
```

Two built-in rules should appear. The first command needs `-t`: the rule keys on a terminal being attached, and a plain `docker exec` is not one. `-it` fails outright without a TTY.

### 9.3 Write a rule the defaults do not have

```yaml
# labs/lab9/falco/rules/custom-rules.yaml
# YOUR TASK: detect a write to /tmp from inside any container
# Requirements:
#   - rule name, desc, priority WARNING, tags [container, drift]
#   - condition: a write, inside a container rather than on the host, under /tmp/
#   - output: container name, user, file and the command line
# Hints:
#   - Falco ships a macro for "opened for writing". Read the shipped rules:
#     docker exec falco grep -A2 'macro: open_write' /etc/falco/falco_rules.yaml
#   - container.id has the value "host" when the event is not in a container
#   - fd.name is the path; `startswith` is a Falco operator
```

<!-- verify:skip needs the rule the student writes in 9.3 -->
```bash
docker kill --signal=SIGHUP falco && sleep 5
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
sleep 6
docker logs falco 2>&1 | grep -c '"rule":"<your rule name>"'
```

SIGHUP reloads rules without restarting the container.

**Submit** in `submissions/lab9.md`, section `## Task 1`:

- The two built-in rules from 9.2, with the alert lines and what triggered each.
- Your rule file, and the alert JSON from 9.3 proving it fired.
- One field in that JSON that would matter during an incident and is not in the human-readable message.
- Three or four sentences: the rule fires on every `/tmp` write in every container. Name a legitimate workload it would flag, and how you would keep the detection while dropping the noise.

## Task 2 — The same rule, before deployment (4 pts)

Optional. Skipping it does not affect later labs.

Falco tells you a container did something. Conftest refuses the manifest before it deploys. Both matter, at different moments.

### 9.4 Read what ships

<!-- verify:nonzero-ok conftest exits non-zero on the unhardened manifest -->
```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
```

The hardened manifest passes 30 checks; the unhardened one fails 8 with 2 warnings. Match each failure to its rule in `labs/lab9/policies/k8s-security.rego`.

The same directory also carries `compose-security.rego`, for the Compose file:

```bash
conftest test labs/lab9/manifests/compose/juice-compose.yml \
  --policy labs/lab9/policies --all-namespaces
```

That one passes all 15 of its checks. A policy set that only ever reports failures teaches you nothing about whether it works, so note what it means that this file passes and the Kubernetes one did not.

### 9.5 Extend the policy

```rego
# labs/lab9/policies/extra/hardening.rego
# YOUR TASK: add two checks the shipped policy does not make
# Requirements:
#   - package the file so conftest picks it up alongside the shipped rules
#   - one deny rule and one warn rule, each with a message naming the container
#   - they must pass on juice-hardened.yaml and fail on a manifest you write
#     specifically to violate them
# Hints:
#   - the shipped policy is the model: read how it walks input.spec.template.spec.containers
#   - candidates the shipped policy misses: image pinned by digest rather than tag,
#     automountServiceAccountToken, a liveness probe, a runAsUser above a threshold
```

<!-- verify:skip needs the policy and manifest the student writes in 9.5 -->
```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test /tmp/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
```

**Submit**, section `## Task 2`:

- The pass and fail counts for both Kubernetes manifests and for the Compose file, and two failures mapped to their Rego rules.
- One sentence on why the same requirement needs a separate rule for Compose and for Kubernetes, and one on what the Compose file passing tells you.
- Your policy file and the manifest you wrote to violate it, with both runs.
- Three or four sentences: the same requirement can be a Conftest rule in CI or a Falco rule at runtime. For the control you just wrote, which one would you keep if you could only have one, and what does the other one still buy you?

## Bonus — Catch a cryptominer (2 pts)

The Tesla incident in Lecture 6 was cryptomining on an exposed cluster. Nobody noticed until a researcher did.

```yaml
# add to labs/lab9/falco/rules/custom-rules.yaml
# YOUR TASK: a rule for likely mining activity
# Requirements:
#   - priority CRITICAL, tags including mitre_command_and_control
#   - combine at least two signals, for example an outbound connection to a
#     typical pool port and a suspicious process name
#   - output must identify the container, the process and the destination
# Hints:
#   - pool ports commonly seen: 3333, 4444, 5555, 7777, 14444
#   - in Falco, fd.sport is the server side of a connection; evt.type=connect
#     with evt.dir=< is the completed attempt
#   - do not connect to a real pool. A refused connection still produces the event
```

<!-- verify:skip needs the bonus rule -->
```bash
docker kill --signal=SIGHUP falco && sleep 5
docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
sleep 6
docker logs falco 2>&1 | grep -c '"priority":"Critical"'
```

**Submit**, section `## Bonus`:

- The rule and the alert it produced.
- Why a refused connection is enough to detect this, and what that implies about where Falco sits.
- Three or four sentences: an attacker who reads your rule picks another port. Which part of this detection is expensive to evade, which is free, and what would you add to catch the evasion?

## Acceptance criteria

- Task 1 (6): Falco running with both built-in rules triggered and quoted; a custom rule that fires, with its JSON; one incident-relevant JSON field named; a concrete false-positive scenario with a tuning plan.
- Task 2 (4): both Kubernetes manifests and the Compose file tested with counts; two failures mapped to Rego rules; the Compose-versus-Kubernetes answer given; your own deny and warn rules passing the hardened manifest and failing a manifest you wrote; the CI-versus-runtime answer commits to a choice.
- Bonus (2): a CRITICAL rule combining two signals, fired and quoted; the refused-connection explanation is correct; the evasion answer distinguishes cheap from expensive changes.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab9.md> (labs/lab9/falco/rules/custom-rules.yaml labs/lab9/policies/extra/ submissions/lab9.md, ...)
git commit -m "feat(lab9): falco custom rules + conftest policy"
git push -u origin feature/lab9
```

Clean up: `docker rm -f falco lab9-target`.


## Common pitfalls

- `docker exec -it` fails with `the input device is not a TTY` outside an interactive shell. Use `-t` alone.
- The terminal-shell rule needs a TTY, so a plain `docker exec` will not trigger it no matter how shell-like the command looks.
- On WSL2 and other kernels missing tracepoints, Falco logs TOCTOU attachment failures at startup. That is not a broken install.
- Rules land in `/etc/falco/rules.d/`, which is mounted read-only from your repository. Edit the file on the host, then SIGHUP.
- A YAML error in your rule file makes Falco reject the whole file. Check `docker logs falco` after every reload.
- Conftest exits non-zero on failures. That is the point in CI, and a trap in a `set -e` script.

## Resources

- [Falco rules reference](https://falco.org/docs/reference/rules/) and [supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- [Falco default rules](https://github.com/falcosecurity/rules) — read before writing your own
- [Conftest](https://www.conftest.dev/) and the [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [MITRE ATT&CK for containers](https://attack.mitre.org/matrices/enterprise/containers/) — where the tags in Falco rules come from
