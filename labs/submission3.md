# Lab 3 — Secure Git

## Task 1 — SSH Commit Signature Verification

### 1.1: Commit Signing Benefits Research

**Why Signing Commits is Critical:**

1. **Authenticity Verification**
   - Proves that a commit was created by the person who claims authorship
   - Prevents attackers from impersonating developers
   - Uses asymmetric cryptography (SSH public/private key pair)

2. **Integrity Protection**
   - Ensures that commit content has not been tampered with after signing
   - Any modification to the commit will invalidate the signature
   - Provides cryptographic proof of commit origin

3. **Non-Repudiation**
   - Developer cannot deny that they created a specific commit
   - Important for audit trails and compliance (ISO 27001, SOC2)
   - Provides accountability in collaborative teams

4. **Supply Chain Security**
   - In DevSecOps, signed commits prevent unauthorized code injection
   - Protects against supply chain attacks (compromised maintainer accounts)
   - Enforced in many open-source projects (Kubernetes, Linux, etc.)

### 1.2: SSH Key Configuration

**SSH Key Details:**
- Algorithm: Ed25519 (modern, secure, recommended)
- Public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOACNAKwtYjr/2m87LNJmaelK3dUf4AG751gy1miTKVG kostikova658@gmail.com`
- Private key location: `~/.ssh/id_ed25519`
- Status: Added to GitHub as Signing Key
![](/labs/screenshots/ssh_key.png)


**Git Configuration for SSH Signing:**
```bash
git config --global user.signingkey ~/.ssh/id_ed25519
git config --global commit.gpgSign true
git config --global gpg.format ssh
```

**Verification Output:**
```
PS D:\INNOPOLIS\DEVSECOPS\DevSecOps-Intro> git config --global --list | Select-String "signingkey|gpgSign|gpg.format"

user.signingkey=~/.ssh/id_ed25519
commit.gpgsign=true
gpg.format=ssh
```

### 1.3: Signed Commit Creation

**Signed Commit Command:**
```bash
git commit -S -m "docs: add commit signing summary"
```

**Local Verification:**
```
PS D:\INNOPOLIS\DEVSECOPS\DevSecOps-Intro> git log -1 --format="%H %G? %GS"
8be815905c7f3a4490e28a57592e07119c3e7ab9 G kostikova658@gmail.com
PS D:\INNOPOLIS\DEVSECOPS\DevSecOps-Intro> git log --show-signature -1
commit 8be815905c7f3a4490e28a57592e07119c3e7ab9 (HEAD -> feature/lab3)
Good "git" signature for kostikova658@gmail.com with ED25519 key SHA256:T2a86HuJ6HCVmxHl1qswf1IWZ4H0ivf5u7mZsIk7wGE
Author: polina193535 <kostikova658@gmail.com>
Date:   Sat Feb 21 16:17:48 2026 +0300

    docs: add commit signing summary
PS D:\INNOPOLIS\DEVSECOPS\DevSecOps-Intro> 
```

**GitHub Verified Commit Evidence:**

![Verified commit screenshot](/labs/screenshots/verified.png)
---

## Why is Commit Signing Critical in DevSecOps Workflows?

### 1. Prevention of Impersonation Attacks
- Without signing, an attacker could set their Git config to use your name/email
- Signed commits provide cryptographic proof of authorship
- Example: Attacker cannot inject malicious code claiming to be you
- Prevents unauthorized code from entering the codebase

### 2. Supply Chain Attack Mitigation
- If a repository is compromised, attackers could inject code
- Signed commits create an audit trail: who made what change and when
- Tools like Cosign and SLSA framework build on commit signing for artifact provenance
- Helps detect unauthorized modifications to critical repositories

### 3. Compliance & Regulatory Requirements
- **ISO 27001:** Requires strong authentication and non-repudiation
- **SOC2:** Demands evidence of access controls and accountability
- **GDPR/HIPAA:** Require audit trails for sensitive data changes
- Many enterprises enforce policies: "All commits to main must be signed"
- Compliance auditors now verify signed commit policies

### 4. Protection Against Maintainer Account Compromise
- Even if an attacker gains access to a GitHub account, they cannot sign commits (without the SSH key)
- Separates authentication (GitHub login) from authorization (SSH signing)
- This is why XZ Utils backdoor (2024) was so dangerous—attacker had signing rights
- SSH keys stored locally provide additional security layer

### 5. CI/CD Pipeline Security
- Deployment systems can verify that only authorized, signed commits are deployed
- Prevents unauthorized code from reaching production
- Integrates with SLSA Level 3+ for supply chain security
- Enables automated enforcement of "all commits must be signed" policies

### Conclusion
In DevSecOps, commit signing is a **foundational control** that ensures every code change is authenticated, authorized, and auditable. It protects against both external attacks and insider threats, making it critical for secure software supply chains.

---

## Task 2 — Pre-commit Secret Scanning

### 2.1: Pre-commit Hook Setup

**Hook Location:** `.git/hooks/pre-commit`

**Configuration Details:**
- Tool 1: **TruffleHog** — scans for high-entropy strings and known secret patterns
- Tool 2: **Gitleaks** — detects hardcoded API keys, tokens, credentials
- Exclusion: Secrets in `lectures/*` files are allowed (educational content)
- Non-lectures files: Any detected secrets block the commit

**Hook Installation:**
```bash
chmod +x .git/hooks/pre-commit
```

### 2.2: Secret Detection Testing

**Test 1: Blocked Commit (with secrets)**

File created: `labs/test-secret.env`
```env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Attempt to commit:**
```bash
git add labs/test-secret.env
git commit -m "test: add test secret"
```

**Result:**
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/test-secret.env
[pre-commit] Non-lectures files: labs/test-secret.env
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
Found unverified result 🐷🔑❓
Detector Type: AWS
Raw result: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
File: labs/test-secret.env
[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files
[pre-commit] Scanning labs/test-secret.env with Gitleaks...
Gitleaks found secrets in labs/test-secret.env:
Finding:     AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Secret:      wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
RuleID:      aws-access-token
File:        labs/test-secret.env
---
✖ Secrets found in non-excluded file: labs/test-secret.env

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: true
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

**Status:**  **BLOCKED as expected**

---

**Test 2: Successful Commit (without secrets)**

File created: `labs/test-clean.env`
```env
APPLICATION_NAME=MyApp
VERSION=1.0.0
```

**Attempt to commit:**
```bash
git add labs/test-clean.env
git commit -m "test: add clean test file"
```

**Result:**
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/test-clean.env
[pre-commit] Non-lectures files: labs/test-clean.env
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning labs/test-clean.env with Gitleaks...
[pre-commit] No secrets found in labs/test-clean.env

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 9be8345] test: add clean test file
 1 file changed, 2 insertions(+)
 create mode 100644 labs/test-clean.env
```

**Status:** **ALLOWED as expected**

---

### Analysis: How Pre-commit Secret Scanning Prevents Security Incidents

#### 1. **Early Detection at Developer Level**
- Secrets are caught **before they reach Git history**
- Once pushed to remote, secrets are very hard to remove completely
- Pre-commit hook acts as the **first line of defense**

#### 2. **Prevents Supply Chain Attacks**
- Hardcoded credentials could be exploited by internal/external attackers
- If a repository is compromised, attackers gain immediate access to:
  - Database credentials
  - API keys for third-party services
  - Cloud provider credentials (AWS, Azure, GCP)
  - Private encryption keys

#### 3. **Compliance & Audit Trail**
- Automated scanning creates **evidence** of security controls
- Meets requirements for ISO 27001, SOC2, HIPAA compliance
- Demonstrates organization takes secrets management seriously

#### 4. **Developer Education**
- Developers learn **not to hardcode secrets** through immediate feedback
- Over time, teams adopt better security practices:
  - Use environment variables for local development
  - Use secrets vaults (HashiCorp Vault, AWS Secrets Manager) for production
  - Never commit `.env` or `credentials.json` files

#### 5. **Cost of Prevention vs. Incident**
- **Prevention cost:** 5-10 seconds per commit for scanning
- **Incident cost:** Credential rotation, audit investigation, potential data breach, reputation damage
- ROI is extremely high

#### Key Incident Prevention Scenarios

| Scenario | Without Hook | With Hook |
|----------|-------------|-----------|
| Developer accidentally commits AWS key |  Secret in Git history forever |  Commit blocked, developer fixes it |
| Contractor with access pushes credentials |  Access to production systems exposed |  Hook prevents push, enforces secure practices |
| CI/CD pipeline leaks API key in logs |  Secret visible in build history |  Hook catches it before it reaches logs |
| Repository accidentally made public |  All historical secrets exposed |  No secrets in history to expose |