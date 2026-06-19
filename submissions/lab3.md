# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration

* `git config --global gpg.format` → `ssh`
* `git config --global user.signingkey` → `/Users/ilyapush/.ssh/id_ed25519.pub`
* `git config --global commit.gpgsign` → `true`

### Local verification

Output of `git log --show-signature -1`:

commit 65e05c9564a2b75ba8330a9bacb730b98a82aa2d (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for ilyapushka4@gmail.com with ED25519 key SHA256:fsuIRoifXBKOrorVGI2V8IcGN71Yg2k57U8QM5Aelww
/Users/ilyapush/.config/git/allowed_signers:1: missing key^M
Author: Ilya <ilyapushka4@gmail.com>
Date:   Fri Jun 19 15:51:32 2026 +0300

    test: first signed commit


### GitHub verification

* Direct link to your most recent commit on GitHub: https://github.com/aylixxx/DevSecOps-Intro/commit/65e05c9564a2b75ba8330a9bacb730b98a82aa2d
* Screenshot of the Verified badge: attached in PR
![Verified Badge](../images/lab3-verified.png)

### One-paragraph reflection

A forged-author commit could allow an attacker or malicious insider to introduce unauthorized code changes while pretending to be another developer. This creates a repudiation problem because it becomes difficult to prove who actually made the change, especially during incident investigations or code reviews. The GitHub Verified badge helps mitigate this risk by cryptographically proving that the commit was signed using a key associated with the author's account, making impersonation attempts much more visible.
