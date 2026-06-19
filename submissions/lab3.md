\# Lab 3 — Submission



\## Task 1: SSH Commit Signing



\### Local configuration

\- `git config --global gpg.format` → ssh

\- `git config --global user.signingkey` → /c/Users/golor/.ssh/id\_ed25519.pub

\- `git config --global commit.gpgsign` → true



\### Local verification

Output of `git log --show-signature -1`:

commit 4526760249b0c61fd70cbb8c140d1f7afb9792a3 (HEAD -> feature/lab3)



Good "git" signature for ruslan.glvv@gmail.com with ED25519 key SHA256:FqT0MdfUde5Ga+7PVLiVjZkytqoC6DF5+cROAR7hhRg



Author: ruslan ruslan.glvv@gmail.com



Date:   Fri Jun 19 11:05:54 2026 +0300



test: first signed commit



\### GitHub verification

\- Direct link to your most recent commit on GitHub: https://github.com/ruslanglvv/DevSecOps-Intro/commit/4526760249b0c61fd70cbb8c140d1f7afb9792a3

\- Screenshot of the Verified badge: <вставь сюда свой скриншот>



\### One-paragraph reflection (2-3 sentences)

A forged-author commit lets an attacker plant malicious code (e.g. a backdoor) while making the commit history show a different, innocent developer as the author — since Git's author/committer fields are just plain text and can be set to anything with git config user.name/email. This is a textbook Repudiation scenario: if the backdoor is later discovered, the real attacker can deny involvement, and suspicion falls on whoever's name was forged. The Verified badge closes this gap by binding each commit to a cryptographic signature from a specific person's private SSH key, which is registered to their GitHub account — so an attacker can spoof the author field, but not the signature, making any forged-author commit immediately visible as Unverified.

