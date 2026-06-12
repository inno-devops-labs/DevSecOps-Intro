# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/jester/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:

### GitHub verification
- Direct link to commit: https://github.com/jestersw/DevSecOps-Intro/commit/7e6ea2d008ba7da97d51e7fd8c459e0c4b161d64
- The commit "test: first signed commit" shows a green **Verified** badge on the `feature/lab3` commits page.

### One-paragraph reflection
A forged-author commit lets an attacker push code under someone else's name — for example, an attacker who gains write access could commit a backdoor and set the author field to a senior engineer's name and email, making it look like that engineer introduced the vulnerability (Repudiation: the real engineer could later deny it, but so could the actual attacker, and the audit trail can't distinguish them). The green Verified badge makes this attack visible because it cryptographically ties the commit to a specific SSH/GPG key that only the real author possesses — an attacker without that private key can set any author name/email they want, but the commit will show as "Unverified," immediately flagging it as suspicious during code review or an incident investigation.