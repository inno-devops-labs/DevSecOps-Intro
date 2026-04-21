# Lab 3 — Secure Git Practices

## Task 1 — SSH Commit Signing

### SSH signing setup

SSH commit signing was configured using an existing `ed25519` SSH key.

Git global configuration:

```bash
git config --global user.signingkey "$HOME/.ssh/id_ed25519.pub"
git config --global commit.gpgSign true
git config --global gpg.format ssh
````

Signed commits were successfully created. During commit creation, Git requested the passphrase for the configured SSH key, confirming that signing was active.

### Why signed commits matter

Signed commits improve repository security by providing:

* **Authenticity** — confirms who created the commit
* **Integrity** — proves the commit was not modified after signing
* **Trust in the supply chain** — helps prevent unauthorized or forged contributions

In a DevSecOps workflow, commit signing is important because it adds traceability and helps protect the codebase from tampering.

---

## Task 2 — Pre-commit Secret Scanning

### Hook setup

A custom `pre-commit` hook was created in:

```text
.git/hooks/pre-commit
```

The hook scans staged files using two Dockerized tools:

* **TruffleHog**
* **Gitleaks**

This ensures secrets can be detected before code is committed.

### Secret scanning tests

#### Test 1 — Fake secret strings

Several test strings were used first, including:

* AWS-style key examples
* GitHub token-like string
* Stripe-like key

These strings were scanned successfully, but they were not detected as secrets by the configured rules in this environment.

#### Test 2 — Blocked commit with Slack bot token

A staged file containing a Slack bot token pattern was scanned:

```text
slack_token = "xoxb-[REDACTED]"
```

The hook output showed:

```text
Gitleaks found secrets in test.txt:
RuleID:      slack-bot-token
...
✖ COMMIT BLOCKED: Secrets detected
```

This confirms that the hook correctly blocks commits when a detectable secret pattern is found.

#### Test 3 — Safe content

A safe file content such as:

```text
safe content only
```

did not trigger the scanners.

This confirms that the hook allows non-secret content while blocking recognized secret patterns.

### Why pre-commit secret scanning matters

Pre-commit secret scanning helps prevent accidental credential leakage before code reaches the repository.

This is important in DevSecOps because:

* leaked secrets can expose cloud resources, APIs, or CI/CD systems
* prevention at commit time is faster and safer than cleaning leaks later
* it enforces secure developer behavior automatically

---

## Conclusion

This lab successfully implemented two secure Git controls:

1. **SSH commit signing**

   * configured successfully
   * signed commits were created

2. **Pre-commit secret scanning**

   * hook created and executed successfully
   * TruffleHog and Gitleaks ran through Docker
   * a Slack bot token pattern was detected
   * the commit was blocked as expected

Overall, the lab demonstrated a secure Git workflow with both commit authenticity and secret leak prevention.