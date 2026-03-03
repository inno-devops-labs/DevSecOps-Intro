# Lab 3 — Secure Git

## Task 1 — SSH Commit Signing

### 1. Benefits of Commit Signing

- Ensures authenticity of commits
- Protects against impersonation
- Ensures commit integrity
- Important in DevSecOps pipelines

### 2. Evidence

#### Command for Key Generation
```bash
ssh-keygen -t ed25519 -C "menshih.maksym@yandex.ru"
```

#### Git Config Output
```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_rsa.pub
```

#### Screenshot of Verified Badge
![Verified Badge](path/to/verified-badge-screenshot.png)

### 3. Analysis

Commit signing is critical in DevSecOps workflows because:
- CI/CD relies on trusted code
- Prevents supply chain attacks
- Ensures traceability
- Supports compliance

## Task 2 — Pre-commit Secret Scanning

### 1. Setup

- Created `.git/hooks/pre-commit`
- Made executable
- Docker required

### 2. Testing

- Added fake AWS key
- Commit blocked
- Removed secret
- Commit allowed

### 3. Analysis

Automated secret scanning prevents incidents by:
- Preventing accidental leaks
- Stopping secrets before they enter history
- Reducing risk of credential compromise
- Supporting shift-left security
