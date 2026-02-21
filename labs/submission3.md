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
```bash
$ git log -1 --format="%H %G? %GS"
<commit-hash> G kostikova658@gmail.com
```

- **G** = Good signature (signed and valid)
- Signature verified with SSH key

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

### Status: In Progress
Pre-commit hook setup to be completed in next iteration.

---