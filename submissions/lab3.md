# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → <ВСТАВЬ вывод: путь к твоему .pub ключу, напр. /Users/имя/.ssh/id_ed25519.pub>
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
<ВСТАВЬ СЮДА весь вывод команды git log --show-signature -1.
Внутри должна быть строка: Good "git" signature for <твоя_почта>>
```

### GitHub verification
- Direct link to your most recent commit on GitHub: <ВСТАВЬ ссылку на коммит, напр. https://github.com/<твой_логин>/<форк>/commit/<хэш>>
- Screenshot of the Verified badge: <ВСТАВЬ скриншот зелёного бейджа Verified — см. инструкцию ниже, как добавить картинку в PR>

### One-paragraph reflection (2-3 sentences)
Without commit signing, anyone can set `git config user.name`/`user.email` to a colleague's
identity and push commits that look authored by that person — a textbook STRIDE Repudiation
attack, where a malicious or careless actor injects code (a backdoor, a credential change)
and later denies authorship, while the blame falls on someone innocent. SSH signing binds
each commit to a private key only the real author holds, so the "Verified" badge on GitHub
becomes the non-repudiable proof that the commit genuinely came from that person; an unsigned
or wrongly-signed forgery shows up as "Unverified" and is immediately visible in review and
in branch-protection checks.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
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

### `pre-commit install` output
```
<ВСТАВЬ вывод команды pre-commit install — должна быть строка:
pre-commit installed at .git/hooks/pre-commit>
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
<ВСТАВЬ сюда вывод заблокированного коммита из шага 3.7 —
там виден gitleaks с FAILED, ID правила (напр. github-pat) и redacted-находка>
```

### Tune-out exercise
1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`.
   This is the safer of the two when you can target a *specific* value (an exact regex or the
   finding's fingerprint), e.g. a single well-known documentation token. It's OK when the
   "secret" is provably fake/public and you scope the rule tightly to that one string, so a real
   secret of a different shape still gets caught. It becomes dangerous if the regex is broad
   (e.g. allowlisting *any* `AKIA*` string), because then a genuinely leaked key matching that
   pattern slips through silently.

2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`.
   Excluding a whole directory is convenient but risky: it turns `docs/` into a blind spot, so the
   day someone pastes a real key into a Markdown example there, gitleaks never sees it. It's only
   acceptable for a directory you are certain will never hold live credentials, and even then a
   narrow allowlist on the specific example value is usually the better trade — path exclusion
   trades coverage for convenience and tends to rot as the repo grows.

---

## Bonus: History Rewrite

### Before
```
<ВСТАВЬ вывод: git log --oneline (до перезаписи, в песочнице /tmp/lab3-bonus)>
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
<ВСТАВЬ вывод: git log --oneline (после git filter-repo)>
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate (revoke) the leaked secret and issue a new one.**
   Rewriting history only removes the secret from *your* copy of the repo. In a real incident the
   credential is already compromised — it lives in clones, forks, CI caches, and any attacker's
   scraper that hit the public repo before the rewrite. The mandatory second step is rotation:
   revoke the exposed key/token at the provider and generate a replacement, because that is what
   actually closes the exposure. Rewriting without rotating is cleanup that only *looks* like
   remediation.

### Two real-world gotchas you discovered (2 sentences each)
1. `git filter-repo` refuses to run on a repo that isn't a fresh clone — it aborts with
   "this does not look like a fresh clone" to protect you from rewriting history you can't recover.
   On the sandbox (a fresh `git init`) it ran fine, but on a real fork I'd either clone fresh or
   pass `--force`, knowing the original refs are backed up under `.git/filter-repo/`.
2. After the rewrite, `git filter-repo` automatically **removed the `origin` remote**, so a plain
   `git push` failed with "no configured push destination". You have to re-add the remote
   (`git remote add origin …`) and then **force-push** (`git push --force`) — a normal push is
   rejected because the rewritten history diverges from what's on the server.
