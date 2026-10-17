# Lab 3 — Secure Git

Branch: `feature/lab3`.

Global SSH signing and the local pre-commit hook are configured. The first
published commit is verified on GitHub, the fake-token commit was blocked,
and the history-rewrite exercise removed both occurrences of the fake secret.

## Task 1

### SSH signing evidence

Global Git signing configuration:

```text
gpg.format=ssh
user.signingkey=C:/Users/Михаил/.ssh/lab3_signing_ed25519.pub
commit.gpgsign=true
tag.gpgsign=true
gpg.ssh.allowedSignersFile=C:/Users/Михаил/.config/git/allowed_signers
```

The allowed-signers file associates the signing keys with
`m.akhmarov@innopolis.university` in the `git` namespace. During initial setup,
a separate local test file was signed with the original `id_ed25519` key using
`ssh-keygen -Y sign` and verified with `ssh-keygen -Y verify`:

```text
Good "git" signature for m.akhmarov@innopolis.university with ED25519 key SHA256:XT+TBD/baTrzkrpwNRA6JMjHhzyhyGXSUh1yGdtm+M0 # gitleaks:allow
```

The trailing `# gitleaks:allow` is an added report annotation, not terminal
output: it exempts this public SSH fingerprint from a `generic-api-key` false
positive. It does not exclude the report or any directory from scanning.

This checks key usability, not a commit signature. The first verification
attempt through a PowerShell text pipeline failed because the pipeline changed
the input bytes; verification using the original file bytes succeeded.

### First signed commit

All three hooks passed when creating `7085ba68c53d4499f4d666bd46270cc3415d026c`.
A dedicated `lab3_signing_ed25519` key was subsequently registered as a GitHub
Signing Key for `etern1ty22` (key ID `1181316`). The original key could not be
registered: GitHub returned `Key is already in use`. After switching the Git
signing configuration, `git commit --amend --no-edit -S` re-signed the first
commit without changing its file contents, producing
`62f2e096482a440922e61891c5edc1377ee4d2f2`.

The output of `git log --show-signature -1` after re-signing was:

```text
commit 62f2e096482a440922e61891c5edc1377ee4d2f2
Good "git" signature for m.akhmarov@innopolis.university with ED25519 key SHA256:sHDC+IYT88czCoQn7JX8901vYi1knuZERXYYNwigPE4 # gitleaks:allow
Author: etern1ty22 <m.akhmarov@innopolis.university>
Date:   Wed Sep 16 16:53:12 2026 +0300

    test: first signed commit
```

As above, the trailing `# gitleaks:allow` is a report annotation for the public
fingerprint, not part of the command output.

`git verify-commit HEAD` also succeeded. The public GitHub signing-key API
confirmed that the registered key matches the local public key.

Published commit: [62f2e09 — test: first signed commit](https://github.com/etern1ty22/DevSecOps-Intro/commit/62f2e096482a440922e61891c5edc1377ee4d2f2).
GitHub reports **Verified**. Its commit API returned:

```json
{
  "verified": true,
  "reason": "valid",
  "verified_at": "2026-09-16T14:11:08Z"
}
```

### Repudiation

In this repository, someone could set an arbitrary Git author name and email
and attribute a weakened Juice Shop deployment configuration or an altered
Lab 2 threat model to another student. A verified signature ties the signed
commit to a key associated with the GitHub account, making author-line forgery
alone insufficient; it does not establish that the changes are secure or that
the signing key was not compromised.

## Task 2

### Hook configuration

The configuration is [`.pre-commit-config.yaml`](../.pre-commit-config.yaml).
The remote tags were checked with `git ls-remote --tags`:

```text
83d9cd684c87d95d656c1458ef04895a7f1cbd8e  refs/tags/v8.30.1
3e8a8703264a2f4a69428a0aa4dcb512790b2c8c  refs/tags/v6.0.0
```

It enables `gitleaks`, `detect-private-key`, and `check-added-large-files`.
Installed tools: pre-commit `4.6.2` and git-filter-repo `2.47.0`, in the ignored
repository-local `.venv`. The gitleaks hook was built from the pinned tag above;
its `version` command reports `version is set by build process` rather than a
release number for this source build.

Commands executed on Windows:

```powershell
./.venv/Scripts/pre-commit.exe install
./.venv/Scripts/pre-commit.exe run --all-files
```

Observed output (installation progress omitted):

```text
pre-commit installed at .git\hooks\pre-commit
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed
```

The all-files run exited with code 1. The flagged file is an existing Lab 6
exercise: lines 10–14 explicitly demonstrate plaintext secrets using a
truncated private-key block. Its directory README confirms that these are
intentionally vulnerable educational fixtures. The fixture was preserved and
no exclusion was added to suppress the finding.

The pinned gitleaks hook invokes `gitleaks git --pre-commit --redact --staged
--verbose`; it scans staged changes even when pre-commit receives `--all-files`.
The index was empty for this run, so its Passed result is not evidence that the
entire working tree or history is free of secrets. The two newly created Lab 3
files were still untracked at this point.

### Blocked fake-token commit

The fake GitHub token from section 3.5 was written to
`submissions/leak-attempt.txt`, and the following commands were run:

```powershell
git add -- submissions/leak-attempt.txt
git -c color.ui=false commit -m "test: should be blocked"
git log --oneline -1
```

Relevant terminal output (ANSI color sequences and the logo omitted):

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

4:54PM INF 0 commits scanned.
4:54PM INF scanned ~48 bytes (48 bytes) in 103ms
4:54PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
Commit exit code: 1
HEAD before: 7085ba68c53d4499f4d666bd46270cc3415d026c
HEAD after:  7085ba68c53d4499f4d666bd46270cc3415d026c
7085ba6 test: first signed commit
```

The nonzero commit exit code and identical HEAD hashes confirm that the token
was not committed. These hashes refer to the original commit before it was
re-signed with the dedicated GitHub signing key. Pre-commit temporarily stashed
the unstaged report edits and restored them after the checks. The test file was
then removed:

```powershell
git restore --staged -- submissions/leak-attempt.txt
Remove-Item -LiteralPath submissions/leak-attempt.txt
```

### Initial commit attempt: public-fingerprint false positive

The first `git commit -m "test: first signed commit"` was blocked before a
commit was created. Gitleaks reported `RuleID: generic-api-key` for the public
SSH SHA256 fingerprint in this report (then line 28); `detect-private-key`
and `check-added-large-files` both passed. A line-scoped `gitleaks:allow`
annotation was added for the known public fingerprint. This false positive is
separate from the successful `github-pat` blocking test above.

### Allowlisting documentation examples

An allowlist entry in `.gitleaks.toml` should match only a reviewed, deliberately
fake example as narrowly as possible. It becomes unsafe if a broad expression
also matches usable credentials or if an allowlisted value is later used as a
real credential; an `AKIA` prefix alone is not a safe exception.

Excluding all of `docs/` suppresses scanning for any credential accidentally
placed there, including copied commands, logs, and configuration examples.
It becomes unsafe as soon as real secrets can enter that directory; narrowly
allowlisting a known fake example retains more protection for other content.

## Bonus

### Sandbox before rewriting

A separate repository was initialized at `%TEMP%\lab3-bonus-20260916`, outside
the course repository. Four commits were created in the order specified in
section 3.6: an empty initial commit, `config.txt` with the fake token, `app.log`,
and `README.md` with the same fake token. All four had valid SSH signatures
before rewriting (`git log --format='%h %G? %s'` reported `G` for each).

`git log --oneline` before rewriting:

```text
de726d4 docs: usage notes
e28c625 feat: empty log
7a6e691 feat: add config
4c0d8ac init
```

The PowerShell equivalent of the assignment's first grep count was:

```powershell
@(git log -p | Select-String -SimpleMatch 'ghp_AAAA').Count
# 2
```

The replacement mapping was prepared in `%TEMP%\lab3-replace-20260916.txt`,
outside the sandbox repository. It maps the exact fake token from section 3.6
to `[REDACTED]`.

### Refusal and rewrite

The first run of `git filter-repo --replace-text` exited with code 1:

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

The repository had multiple HEAD reflog entries from its four local commits.
After checking that the repository root was the disposable sandbox outside the
course repository, the command was repeated with `--force`:

```powershell
# Run from %TEMP%\lab3-bonus-20260916 only.
C:/Documents/DevSecOps-Intro/.venv/Scripts/git-filter-repo.exe --replace-text "$env:TEMP/lab3-replace-20260916.txt" --force
```

The rewrite completed successfully and reported repacking and cleaning out old
unneeded objects. `git log --oneline` afterward:

```text
f9dfda4 docs: usage notes
7fcdf4d feat: empty log
764af53 feat: add config
bd780cf init
```

Measured counts:

| Measurement in `git log -p` | Count |
| --- | ---: |
| `ghp_AAAA` before rewriting | 2 |
| `ghp_AAAA` after rewriting | 0 |
| `REDACTED` after rewriting | 2 |

The after-rewrite counts were obtained with:

```powershell
@(git log -p | Select-String -SimpleMatch 'ghp_AAAA').Count
@(git log -p | Select-String -SimpleMatch 'REDACTED').Count
```

### Two observations

1. A repository created just for this exercise still triggered the freshness
   refusal: the terminal specifically cited multiple HEAD reflog entries.
   Being newly created is not the same as satisfying the fresh-clone check.
2. `git log --format='%h %G? %s'` changed from `G` for all four commits to `N`
   for all four after rewriting. The rewritten commits were unsigned, even
   though global automatic signing remained enabled, and even the empty
   `init` commit received a new hash.

### Credential rotation

The exposed credential must be revoked or rotated, and consumers updated to
use the replacement. Rewriting history alone cannot invalidate copies already
obtained from clones, forks, caches, or logs.
