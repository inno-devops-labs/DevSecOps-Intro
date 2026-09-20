# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

**Environment:**
- Windows 11 host, Git Bash, `git version 2.53.0.windows.2` (SSH signing needs 2.34+).
- `pre-commit 4.6.2` and `git-filter-repo 2.47.0`, both installed with `python -m pip install` under Python 3.14.3. `pipx` is not installed here and Windows Python is not PEP 668 "externally managed", so a plain `pip install` was enough.
- `gitleaks` is not installed as a system binary. The `gitleaks` pre-commit hook is `language: golang`, so pre-commit downloaded a Go toolchain (`go1.27.1 windows/amd64`) and built `gitleaks.exe` v8.30.1 into its own cache.
- Tokens in this report are truncated on purpose: a full `ghp_...` string in this file would be caught by the very hook installed in Task 2 and would block the commit.

## Task 1

### 3.1–3.2 Configuration

```bash
git config --global --get-regexp 'gpg|signingkey|gpgsign'
```

```text
user.signingkey C:/Users/Evgenii/.ssh/id_ed25519.pub
gpg.format ssh
commit.gpgsign true
tag.gpgsign true
gpg.ssh.allowedsignersfile C:/Users/Evgenii/.config/git/allowed_signers
```

| Key | Value |
|---|---|
| `gpg.format` | `ssh` |
| `user.signingkey` | `C:/Users/Evgenii/.ssh/id_ed25519.pub` (a fresh `ed25519` key, `SHA256:xOEm0thbWW909lmTgA/Pe6UuGDytLYh3B/v/3hRrYc4`) |
| `commit.gpgsign` | `true` |

Git rewrote the `~` I typed into an absolute `C:/Users/...` path when it stored both paths.

`~/.config/git/allowed_signers` holds one line, which is what makes local verification possible at all:

```text
genya.moskal@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqyiQk00zggNqeHrB/tm5rA9bUZjC30MamzhumGYGCl genya.moskal@gmail.com
```

The same public key is registered on GitHub a second time, as **Key type: Signing Key** — the authentication copy does not count for verification.

### 3.3 Proof

```bash
echo "lab3" > submissions/lab3.md
git add submissions/lab3.md
git commit -m "test: first signed commit"
git log --show-signature -1
```

```text
commit f8767ae5e03575b8c9178bbea0f5539212d6755a
Good "git" signature for genya.moskal@gmail.com with ED25519 key SHA256:xOEm0thbWW909lmTgA/Pe6UuGDytLYh3B/v/3hRrYc4
Author: mobgun <genya.moskal@gmail.com>
Date:   Sun Sep 20 18:06:36 2026 +0300

    test: first signed commit
```

Commit on GitHub with the **Verified** badge:
<https://github.com/mobgun/DevSecOps-Intro/commit/f8767ae5e03575b8c9178bbea0f5539212d6755a>

### Repudiation

The author line is plain text that anyone can set with `git config user.name`, so a contributor to this fork could push a commit that weakens, say, the Lab 6 IaC checks or the PR workflow in `.github/`, put my name and address on it, and the history would read as if I made that change — and I would have no way to prove otherwise, which is the repudiation half of STRIDE. The signature changes the claim from "this commit says it is mine" to "this commit was made by someone holding my private key", because `git log --show-signature` and GitHub's **Verified** badge both check the commit bytes against the public key in `allowed_signers` / my GitHub signing keys. My Lab 2 Threagile run produced no explicit **R** row (its top five were E, I, I, T, I) — Threagile models the running Juice Shop, not the repository that ships it, and the repository is exactly where repudiation lives.

## Task 2

### 3.4 `.pre-commit-config.yaml`

```yaml
# Lab 3 — block secrets before they leave the laptop.
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

`v8.30.1` is the current gitleaks 8.x release and `v6.0.0` the current `pre-commit-hooks` tag. `check-added-large-files` keeps its default 500 kB limit; the largest tracked file in the repo is a 24 kB lecture, so nothing legitimate is near it.

### 3.5 Install and baseline run

```bash
pre-commit install
pre-commit run --all-files
```

```text
pre-commit installed at .git\hooks\pre-commit
[INFO] Initializing environment for https://github.com/gitleaks/gitleaks.
[INFO] Installing environment for https://github.com/gitleaks/gitleaks.
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed
```

The one failure is upstream course material, not my work: `labs/lab6/vulnerable-iac/ansible/configure.yml` ships a deliberately vulnerable Ansible file with a PEM `PRIVATE KEY` block (and `admin_password: "Admin123!"` next to it) as the fixture Lab 6 is supposed to find. I left the hook strict rather than excluding that path: the installed hook runs on *staged* files, so an upstream fixture I never touch cannot block a commit, and `--all-files` correctly reports it.

### The blocked commit

```bash
printf 'GH_PAT=ghp_16C7...B4a\n' > submissions/leak-attempt.txt   # the full fake PAT from the lab text
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked"
```

```text
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
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

6:20PM INF 0 commits scanned.
6:20PM INF scanned ~48 bytes (48 bytes) in 58.7ms
6:20PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

`git commit` exited 1 and the rule is named: **`github-pat`**. The secret itself never reaches the terminal because the hook runs gitleaks with `--redact`.

Proof that nothing was committed:

```bash
git log --oneline -1
git status --short
```

```text
f8767ae test: first signed commit
A  submissions/leak-attempt.txt
```

HEAD is still the Task 1 commit; the leak file only ever existed in the index and the working tree. Cleanup:

```bash
git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt
```

### Allowlist vs. path exclusion for `AKIA...` documentation examples

**`[allowlist]` in `.gitleaks.toml`.** The narrow form targets the value, not the place: a `regexes` entry for the exact literal (`AKIAIOSFODNN7EXAMPLE`), or a `stopwords` entry, so that one string stops firing anywhere in the repo while every other AWS key id still does. It is reviewable — the exception is a line in a committed config and it shows up in a diff. It stops being safe as soon as the pattern is widened to something like `AKIA[A-Z0-9]{16}`, because then the allowlist matches real keys too and the scanner goes quiet exactly when it should not. (Gitleaks already allowlists the AWS documentation keys by default, which is why the lab needed a `ghp_` token to get a hit at all.)

**A path exclusion for `docs/`.** `paths = ['''^docs/''']` is one line and needs no thought about formats, so it is tempting for a folder that is "only examples". But it turns off *every* rule for everything under that path, forever, including files nobody has written yet. It stops being safe the moment `docs/` stops being purely illustrative — a runbook that pastes a real support token, a generated API reference, an `.env.example` someone fills in. The blind spot is also attractive on purpose: anyone who knows the exclusion exists knows where a secret can be parked without tripping CI.

In short: allowlist the *value* when the value is genuinely public and inert; exclude the *path* only for content that is machine-generated or throwaway, and revisit it, because a path exclusion is a standing promise about files that do not exist yet.

### The same decision, forced by this report

Committing this file failed on the hook I had just installed:

```text
Finding:     ...il.com with ED25519 key SHA256:REDACTED
Secret:      REDACTED
RuleID:      generic-api-key
Entropy:     4.879526
File:        submissions/lab3.md
Line:        52
```

Line 52 is the `git log --show-signature` output pasted into Task 1. `generic-api-key` sees the word `key`, a `:`, and 43 high-entropy characters, and cannot tell that they are the fingerprint of a **public** key — the one value in this whole lab that is meant to be published. So the choice from the previous section stopped being theoretical, with three ways out:

- exclude `submissions/` — the unsafe one, and the most tempting: every future report is then unscanned, and reports are exactly where people paste terminal output;
- drop the fingerprint from the evidence — quiet, but it removes the proof the task asks for;
- allowlist that one literal value.

I took the third:

```toml
# .gitleaks.toml
[extend]
useDefault = true

[[allowlists]]
description = "SSH signing key fingerprint of mobgun (public value, quoted in submissions/lab3.md)"
regexTarget = "line"
regexes = [
  '''SHA256:xOEm0thb...rYc4''',
]
```

The regex is the full fingerprint literal, so it silences that string and nothing else: any other high-entropy value on any other line, in this file or any future one, still fails the commit. If I ever rotate the signing key, this entry stops matching and becomes dead config rather than a widening hole — which is the property a path exclusion does not have. After adding it, all three hooks pass and the commit goes through.

## Bonus

### 3.6 Sandbox and planted secret

The sandbox is a throwaway repo outside the fork (a scratch directory on this Windows host, the equivalent of `/tmp/lab3-bonus`), built exactly as in the lab: an empty `init`, `config.txt` with the key, an unrelated `app.log`, then the same key appended to `README.md`.

```bash
git log --oneline
```

```text
abe3033 docs: usage notes
e430d9f feat: empty log
a2587ab feat: add config
419b0d6 init
```

```bash
git log -p | grep -c 'ghp_AAAA'
```

```text
2
```

### 3.7 Rewrite

First attempt, without `--force`:

```bash
echo 'ghp_AAAABBBB...IIIIJJ==>[REDACTED]' > ../replace.txt   # the full token on the left
git filter-repo --replace-text ../replace.txt
```

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

What it is actually complaining about is the line in parentheses: it counts **reflog entries for HEAD**, not remotes, and this repo has four commits' worth of them. The rail exists because a rewrite throws away everything that is only reachable from the reflog or from another branch, with no undo. In a sandbox I built myself two minutes earlier there is nothing to lose, so `--force` is the documented answer here. In a real incident I would do the opposite of forcing: run the rewrite on a fresh `git clone --mirror`, exactly as the message suggests.

```bash
git filter-repo --replace-text ../replace.txt --force
```

```text
Parsed 4 commits
HEAD is now at ca8ba1a docs: usage notes

New history written in 0.16 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
Completely finished after 0.49 seconds.
```

`git log --oneline` after:

```text
ca8ba1a docs: usage notes
ead9790 feat: empty log
58abe9c feat: add config
3280b32 init
```

Same four subjects, four new hashes — every commit from the first touched one onward was rebuilt.

| Command | Before | After |
|---|---|---|
| `git log -p \| grep -c 'ghp_AAAA'` | 2 | **0** |
| `git log -p \| grep -c 'REDACTED'` | — | **2** |

Both copies of the key — the one in `config.txt` and the one appended to `README.md` — are gone from every reachable blob, replaced by the marker.

### The step that ends the incident

**Rotating the credential**: revoke that token at the provider and issue a new one. The rewrite only changes what *this* repository hands out from now on; it does nothing to the secret itself, and the secret is what has value. By the time the rewrite runs, the old objects may still sit in every teammate's clone and reflog, in forks, in CI caches and build logs, and in GitHub's unreachable-object storage, where a commit stays fetchable by its SHA until it is garbage-collected — which is why the GitHub docs tell you to contact Support. Anything that scraped the public repo between the push and the cleanup already has it. A token that is still valid is still a way in, no matter how clean `git log` looks. The rewrite is damage limitation for the future; rotation is what closes the door. Only then does the rest of the cleanup matter — re-add the remote, force-push, have every collaborator re-clone, expire the reflogs.

### Two things that surprised me

1. **The rewrite quietly threw away both the signatures and the remote.** Every commit in the sandbox was signed, because Task 1 set `commit.gpgsign` globally — and after `filter-repo` the new HEAD prints no signature line at all in `git log --show-signature`. The commit objects were rebuilt, so the old signatures no longer match anything and are simply dropped. Then `git remote -v` came back empty: I added an `origin` and re-ran the rewrite to check, and filter-repo removed it without printing a word. That is deliberate — it stops you from force-pushing a rewritten history by reflex — but it means a real cleanup ends with `git remote add origin ...`, a force push, *and* re-signing whatever has to stay Verified. History rewriting and commit signing pull against each other.
2. **Installing "a scanner" downloaded a compiler.** The `gitleaks` pre-commit hook is `language: golang`, so `pre-commit run --all-files` sat on a silent `[INFO] Installing environment for https://github.com/gitleaks/gitleaks.` for about thirteen minutes while it fetched Go 1.27.1 and built `gitleaks.exe` from source, leaving a 289 MB `~/.cache/pre-commit`. The second surprise was hidden inside that run: the scanner's first honest finding was not in my work at all but in `labs/lab6/vulnerable-iac/ansible/configure.yml` — the course repository ships a private key as a teaching fixture, and the brand-new hook found it on its first pass.
