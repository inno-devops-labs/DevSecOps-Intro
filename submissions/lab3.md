# Lab 3 — Submission

_Secure Git: Signed Commits, Secret Scanning, and History Hygiene._

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/hermit/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`
- `git config --global tag.gpgsign` → `true`
- `git config --global gpg.ssh.allowedSignersFile` → `/Users/hermit/.config/git/allowed_signers`

`~/.config/git/allowed_signers`:

```
albertmuha01@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID19nBQ0WWWb3/KIOqZqZbcuez69pbJ03ga79oLzjMNU albertmuha01@gmail.com
```

### Local verification
Output of `git log --show-signature -1`:

```
commit cfd3f178adbcbffe87e86d78cff39f587ceecee2
Good "git" signature for albertmuha01@gmail.com with ED25519 key SHA256:Cm8lnomYhFB1PvTJDe/71/FO6BAmIBPjtFHuW+lX18s
Author: albert-de-swerto <albertmuha01@gmail.com>
Date:   Fri Jun 19 19:40:07 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to the commit on GitHub:
  <https://github.com/alberto-de-swerto/DevSecOps-Intro/commit/cfd3f178adbcbffe87e86d78cff39f587ceecee2>
- The public key was uploaded under the **Signing Key** role (GitHub → Settings → SSH and GPG keys),
  which is what makes the badge turn green — the same key under only "Authentication Key" would still show *Unverified*.
- Verified badge — confirmed via the GitHub REST API (`GET /repos/.../commits/{sha}` → `commit.verification`),
  which is the authoritative source behind the green badge shown on the commit page above:

```
sha      = cfd3f178adbcbffe87e86d78cff39f587ceecee2
html_url = https://github.com/alberto-de-swerto/DevSecOps-Intro/commit/cfd3f178adbcbffe87e86d78cff39f587ceecee2
verified = True
reason   = valid
```

> Every commit on this branch is signed with the same key, so each one shows the green **Verified** badge on GitHub.

### One-paragraph reflection (STRIDE-R / Repudiation)
Git trusts whatever `user.name`/`user.email` you set, so by default any author identity is forgeable: an attacker (or a careless insider) can push a commit that *looks* like it came from the tech lead — say, slipping a backdoor into the auth module — and then plausibly deny it ("I never wrote that") or pin the blame on the impersonated developer. That is textbook STRIDE **Repudiation**: an action with no trustworthy attribution. The **Verified** badge breaks the attack by cryptographically binding each commit to a key GitHub knows belongs to the account; a forged-author or unsigned commit then shows **Unverified**, making the impersonation visible in code review and enforceable at the gate (branch protection's "Require signed commits") instead of silently entering history.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

```yaml
# Lab 3 — pre-commit guardrails
# Catches secrets and dangerous files *before* they leave the laptop.
# Run once after cloning:  pre-commit install
# Sanity check the whole tree:  pre-commit run --all-files

# pre-commit >= 4 renamed the "commit" stage to "pre-commit".
default_stages: [pre-commit]

repos:
  # Secret scanner — the control that would have stopped Toyota's T-Connect leak.
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1            # pinned v8.x release tag
    hooks:
      - id: gitleaks

  # Belt-and-braces hooks from the pre-commit project itself.
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key        # blocks committing a raw private key
      - id: check-added-large-files   # blocks accidentally adding huge blobs
        args: ["--maxkb=1024"]
```

### `pre-commit install` output

```
pre-commit installed at .git/hooks/pre-commit
```

First run (builds the hook environments, then all three pass on a clean file):

```
[INFO] Initializing environment for https://github.com/gitleaks/gitleaks.
[INFO] Initializing environment for https://github.com/pre-commit/pre-commit-hooks.
[INFO] Installing environment for https://github.com/gitleaks/gitleaks.
[INFO] Installing environment for https://github.com/pre-commit/pre-commit-hooks.
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit
A file containing a GitHub-PAT-style fake secret (`ghp_16C7e42F…` — a `ghp_` prefix + 36 chars, the format
the lab specifies because the canonical `AKIAIOSFODNN7EXAMPLE` value is gitleaks-allowlisted) was staged and
`git commit` was attempted. _(The literal value is truncated here so this submission file itself stays clean —
gitleaks redacts findings for exactly this reason.)_ gitleaks aborted the commit (ANSI colors stripped):

```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

7:43PM INF 0 commits scanned.
7:43PM INF scanned ~101 bytes (101 bytes) in 23.4ms
7:43PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

The commit never landed (`git log -1` still pointed at the previous commit), and the planted file
was then unstaged and deleted — the fake secret was never committed, not even with `--no-verify`.

### Tune-out exercise
A teammate insists they must commit `AKIA*` strings because they are documentation examples in `docs/`.

1. **Inline allowlist** — an `[allowlist]` block in `.gitleaks.toml` (a `regexes`/`stopwords` entry, or
   pinning the specific `fingerprint`). This is OK when the matched string is *provably* a non-secret you can
   pin precisely — a canonical placeholder, a known-public sample key, or one specific test fixture — and you
   scope the rule to that exact value/fingerprint. It stays in the repo, so it's auditable and shows up in review.
   It becomes dangerous the moment the regex is loose (e.g. allowlisting *all* `AKIA…` strings), because then a
   genuinely live key matching the same shape would sail straight through undetected.

2. **Path exclusion** — `paths` (or `[allowlist] paths = ['docs/']`) in `.gitleaks.toml`. Convenient when an
   entire directory is secret-free by design (generated fixtures, vendored third-party content). It's risky
   because it's coarse and permanent: scanning is switched off for that whole subtree forever, so the day
   someone pastes a real credential into a `docs/` runbook or README example — one of the most common ways
   secrets actually leak — it ships completely unscanned. Prefer the narrowest allowlist (exact regex or
   fingerprint) over excluding a path whenever you can.

> **I actually hit this:** gitleaks flagged the *public* SSH key fingerprint in my pasted `show-signature`
> output as a `generic-api-key`. I used **approach 1** — see [`.gitleaks.toml`](../.gitleaks.toml): an
> `[extend] useDefault = true` config with a single allowlist regex matching only that one literal public
> fingerprint. A control test confirms a real `ghp_…` PAT is still caught, so the allowlist masks exactly one
> provably-non-secret string and nothing else — the safe end of the tradeoff above.

---

## Bonus: History Rewrite

Performed on a throwaway `/tmp/lab3-bonus` sandbox (a fresh `git init`, **not** the course fork).
The secret (`ghp_AAAA…IIIIJJ`, a `ghp_` + 36-char string; full value truncated here so this file stays clean)
was planted across two commits.

### Before

```
f2b2f5a docs: add usage notes
249c452 feat: empty log
d748286 feat: add config
8db3f3b init
```

Output of `git log -p | grep -c 'ghp_AAAA'`: **2**

### After (`git filter-repo --replace-text /tmp/replace.txt --force`)

```
a579bbc docs: add usage notes
45e3140 feat: empty log
4d470a1 feat: add config
8db3f3b init
```

Output of `git log -p | grep -c 'ghp_AAAA'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

The redacted lines now read `API_KEY=[REDACTED]` in both the `config.txt` and `README.md` history.

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite history locally to scrub the secret.
2. **Rotate (revoke + reissue) the leaked credential** — this is the mandatory second step.
   Rewriting history and force-pushing only cleans *your* tree; the secret was already exposed the instant it
   was pushed and now lives in every existing clone and fork, in GitHub's cached commit/PR views and fork
   network, in CI logs, and almost certainly in automated scrapers that scan public pushes within seconds.
   The only real remediation is to **revoke the old secret and generate a new one** — rewrite is hygiene,
   rotation is the fix.

### Two real-world gotchas I hit
1. **filter-repo refused to run on my sandbox.** It aborted with
   *"Refusing to destructively overwrite repo history since this does not look like a fresh clone
   (expected at most one entry in the reflog for HEAD)."* My sandbox had four commits — and therefore several
   HEAD reflog entries — so filter-repo treated it as "not fresh" and made me re-run with `--force` to rewrite
   in place. (This is filter-repo's guardrail against accidentally nuking the wrong repo; it expects you to run
   on a *fresh clone*.)
2. **Every commit SHA from the first match onward changed.** `feat: add config` went `d748286 → 4d470a1`,
   and that cascade flipped the later `docs` commit `f2b2f5a → a579bbc`, while the pre-secret `init` commit
   kept its original SHA `8db3f3b`. So a rewrite invalidates *all* downstream hashes (and drops any signatures
   on those commits) — which means every collaborator's existing clone has now diverged and must `reset --hard`
   or re-clone; they can't just `git pull`. That collaboration cost is exactly why rewrite is a last resort.
