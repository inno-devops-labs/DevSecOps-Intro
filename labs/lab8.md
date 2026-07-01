# Lab 8 — Supply Chain Security: Cosign Sign + SBOM Attestation + Blob Signing

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Supply%20Chain-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Cosign%20%2B%20Sigstore-informational)

> **Goal:** Sign the Juice Shop image with Cosign in a local registry, attach the CycloneDX SBOM from Lab 4 as an attestation, and (bonus) sign a tarball using `cosign sign-blob` to mitigate the Codecov 2021 attack class.
> **Deliverable:** A PR from `feature/lab8` with `submissions/lab8.md` + saved verification outputs. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- **Local Distribution v3 registry** — running your own OCI registry
- **Cosign v3.x** — keyed signing of an image digest + tamper demonstration
- **In-toto attestation predicates** — CycloneDX SBOM + minimal provenance
- (Bonus) **`cosign sign-blob`** — what would have stopped the Codecov 2021 attack

> Recall Lecture 8 slide 1 — xz-utils 2024 narrowly missed shipping a backdoor to millions of sshd daemons. The signing + attestation pattern you build today is the discipline (not silver bullet) that supply-chain attacks bypass when absent.

---

## Project State

**You should have from Labs 1, 4, 7:**
- Juice Shop v20.0.0 image (Lab 1)
- `labs/lab4/juice-shop.cdx.json` — CycloneDX SBOM (Lab 4 Task 1)
- `labs/lab4/juice-shop-attestation.json` — sign-ready predicate (Lab 4 Bonus, if completed)
- Trivy image scan output (Lab 7 Task 1)

**This lab adds:**
- A local registry holding the image
- A Cosign keypair + signature + saved verification output
- SBOM attestation attached to the image (this is the Lab 4 SBOM finally in its final form)
- (Bonus) A signed tarball + verification

---

## Setup

You need:
- **Docker**
- **Cosign v3.x** — `brew install cosign` or [GitHub releases](https://github.com/sigstore/cosign/releases) (course pins v2.4.x as of April 2026)
- **`jq`**

```bash
git switch main && git pull
git switch -c feature/lab8

cosign version    # Should print 2.x.x
docker --version

mkdir -p labs/lab8/keys labs/lab8/results
```

---

## Task 1 — Local Registry + Cosign Sign + Tamper Demo (6 pts)

**Objective:** Run a local OCI registry, push Juice Shop into it, sign with Cosign, and demonstrate that re-tagging breaks the signature.

### 8.1: Start the local registry + push Juice Shop

```bash
# Distribution v3 — the modern reference registry (replaces v2)
docker run -d --name lab8-registry \
  -p 127.0.0.1:5000:5000 \
  registry:3

# Pull Juice Shop (if not already present)
docker pull bkimminich/juice-shop:v20.0.0

# Tag and push to local registry
docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0

# Capture the registry digest — you'll sign this, not the tag
docker inspect localhost:5000/juice-shop:v20.0.0 \
  --format '{{index .RepoDigests 0}}' > labs/lab8/results/juice-shop-digest.txt
cat labs/lab8/results/juice-shop-digest.txt
# Should be: localhost:5000/juice-shop@sha256:abc... (KEEP THIS — used in every step)
```

### 8.2: Generate a Cosign keypair

```bash
cd labs/lab8/keys
cosign generate-key-pair    # Will prompt for a passphrase; use something memorable
cd -

# Verify both files exist
ls labs/lab8/keys/
# Should show: cosign.key (private — DO NOT COMMIT) and cosign.pub
```

> **The `cosign.key` is a private key. Your pre-commit hook (Lab 3 gitleaks) should refuse to commit it.** Test this — try `git add labs/lab8/keys/cosign.key` and watch gitleaks block the commit.

### 8.3: Sign the image (digest, not tag)

```bash
# Read the digest captured above
DIGEST=$(cat labs/lab8/results/juice-shop-digest.txt)
echo "Signing: $DIGEST"

# Sign with your private key
COSIGN_PASSWORD="<your-passphrase>" cosign sign \
  --key labs/lab8/keys/cosign.key \
  --yes \
  "$DIGEST"

# Verify
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  "$DIGEST" | tee labs/lab8/results/verify-original.json
# Should print verification claims; exit 0
```

> **Why `--insecure-ignore-tlog`?** We're not pushing to the public Rekor transparency log for this lab (no upstream identity for the local registry). For real keyless signing in CI (Lecture 8 slide 7), Rekor handles this automatically.

### 8.4: Tamper demonstration

```bash
# Pull a different image
docker pull alpine:3.20
# Re-tag it to LOOK like Juice Shop
docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0-tampered

# Push under the same name
docker push localhost:5000/juice-shop:v20.0.0-tampered

# Re-resolve digest — it's DIFFERENT (alpine is not juice-shop)
docker inspect localhost:5000/juice-shop:v20.0.0-tampered \
  --format '{{index .RepoDigests 0}}'
# Should be a different sha256:...

# Verify the tampered image — should FAIL
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  "localhost:5000/juice-shop@$(docker inspect localhost:5000/juice-shop:v20.0.0-tampered --format '{{index .RepoDigests 0}}' | cut -d@ -f2)" \
  > labs/lab8/results/verify-tampered.txt 2>&1 || true

# The verify-tampered.txt should contain "no matching signatures" or similar
cat labs/lab8/results/verify-tampered.txt
```

### 8.5: Sanity — original still works

```bash
# Original digest still verifies
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  "$DIGEST"
# Should succeed — the signature is digest-bound, not tag-bound
```

### 8.6: Document in `submissions/lab8.md`

````markdown
# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: <paste contents of labs/lab8/results/juice-shop-digest.txt>

### Signing
- Output of `cosign sign` (just the success line is fine):
```
<paste>
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
<paste labs/lab8/results/verify-original.json>
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
<paste labs/lab8/results/verify-tampered.txt — must contain "no matching signatures">
```

### Sanity — original still verifies
```
<paste the second cosign verify success>
```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the
ORIGINAL digest. What would have broken if Cosign had signed the tag instead?
````

---

## Task 2 — SBOM + Provenance Attestations (4 pts)

> ⏭️ Optional. Skipping won't affect future labs but you lose the Lab 4 → Lab 10 SBOM chain.

**Objective:** Attach the Lab 4 SBOM and a minimal provenance attestation to the image. Verify both.

### 8.7: Attach SBOM as a CycloneDX attestation

```bash
DIGEST=$(cat labs/lab8/results/juice-shop-digest.txt)

# Use the Lab 4 SBOM as the predicate
cosign attest \
  --key labs/lab8/keys/cosign.key \
  --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --yes \
  "$DIGEST"

# Verify the attestation + extract the embedded SBOM
cosign verify-attestation \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  --type cyclonedx \
  "$DIGEST" | jq -r '.payload | @base64d | fromjson | .predicate' \
  > labs/lab8/results/sbom-from-attestation.json

# Compare to Lab 4 source
diff <(jq -S '.components | length' labs/lab4/juice-shop.cdx.json) \
     <(jq -S '.components | length' labs/lab8/results/sbom-from-attestation.json)
# Should print nothing — same content
```

### 8.8: Attach a minimal provenance attestation

> **Cosign v3 note:** `cosign attest --type slsaprovenance` expects ONLY the predicate body (not the full in-toto envelope). Cosign wraps your predicate in the envelope automatically.

```bash
# Write the SLSA-provenance-v0.2 predicate body only
cat > /tmp/predicate-only.json <<EOF
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/student/repo",
      "digest": { "sha1": "abc123" }
    }
  }
}
EOF

cosign attest \
  --key labs/lab8/keys/cosign.key \
  --type slsaprovenance \
  --predicate /tmp/predicate-only.json \
  --tlog-upload=false \
  --allow-insecure-registry \
  --yes \
  "$DIGEST"

# Verify
cosign verify-attestation \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  --type slsaprovenance \
  "$DIGEST" > labs/lab8/results/provenance-verify.json
```

### 8.9: Document in `submissions/lab8.md`

````markdown
## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
<paste — must show _type, subject, predicateType, predicate with components>
```
- Component count matches Lab 4 source: yes / no
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `<output>` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `<your value>`
- buildType in predicate: `<your value>`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?
````

---

## Bonus Task — Blob Signing (Codecov 2021 Mitigation) (2 pts)

> 🌟 **Practical & directly maps to a real incident.** The Codecov bash uploader was distributed via `curl | bash` without verification. `cosign sign-blob` is the API that would have stopped it.

**Objective:** Sign a tarball with `cosign sign-blob`, distribute the signature alongside it, and verify on a fresh download.

### B.1: Make a "release" artifact

```bash
# Pretend this is your release script
cat > /tmp/install.sh <<'EOF'
#!/bin/bash
echo "Welcome to my-cool-tool installer"
echo "Running setup..."
EOF
chmod +x /tmp/install.sh

# Tar + gzip it
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh
```

### B.2: Sign the blob

```bash
# Sign — produces a .sig file and a .pem certificate (for keyless) or just .sig (for keyed)
cosign sign-blob \
  --key labs/lab8/keys/cosign.key \
  --yes \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz

# Show what was produced
ls labs/lab8/results/my-tool.tar.gz*
```

### B.3: Distribute + verify (simulating a fresh download)

```bash
# Copy to a "fresh" directory as if downloaded
mkdir -p /tmp/fresh-download
cp labs/lab8/results/my-tool.tar.gz \
   labs/lab8/results/my-tool.tar.gz.bundle \
   labs/lab8/keys/cosign.pub \
   /tmp/fresh-download/

cd /tmp/fresh-download/

# Verify
cosign verify-blob \
  --key cosign.pub \
  --bundle my-tool.tar.gz.bundle \
  --insecure-ignore-tlog \
  my-tool.tar.gz
# Should print "Verified OK" and exit 0
cd -
```

### B.4: Tamper test for the blob

```bash
# Modify the blob (simulating an attacker re-distributing a malicious version)
cp labs/lab8/results/my-tool.tar.gz /tmp/fresh-download/my-tool.tar.gz
echo "MALICIOUS PAYLOAD" >> /tmp/fresh-download/my-tool.tar.gz

cd /tmp/fresh-download/
cosign verify-blob \
  --key cosign.pub \
  --bundle my-tool.tar.gz.bundle \
  --insecure-ignore-tlog \
  my-tool.tar.gz 2>&1 | tee /tmp/blob-tamper.txt || true
# Should FAIL — signature was bound to the original byte stream
cd -

cat /tmp/blob-tamper.txt    # paste this into submission
```

### B.5: Document in `submissions/lab8.md`

````markdown
## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
<paste — must include "Verified OK">
```

### Tamper test failed (correctly)
```
<paste /tmp/blob-tamper.txt — must show "Error: ..." or "signature was invalid">
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via `curl | bash` without signature verification.
If their CI consumers had been running `cosign verify-blob` before `bash`-ing the script,
how would the attack have failed? Reference Lecture 8 slide 14 + the specific cosign command
that would have caught it.
````

---

## How to Submit

```bash
git add labs/lab8/keys/cosign.pub          # PUBLIC key OK to commit (private key is gitignored)
git add submissions/lab8.md
git commit -m "feat(lab8): cosign sign + SBOM/provenance attestations + blob signing"
git push -u origin feature/lab8

# Cleanup
docker stop lab8-registry && docker rm lab8-registry
```

> **CRITICAL: NEVER commit `labs/lab8/keys/cosign.key`** — gitleaks should already block it. Verify your `.gitignore` excludes `*.key` patterns.

PR checklist body:

```text
- [x] Task 1 — Image signed + tamper demo (both shown)
- [ ] Task 2 — SBOM + provenance attestations attached and verified
- [ ] Bonus — Blob signed + verify-blob success + tamper failure
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Local registry running; Juice Shop pushed with a captured registry digest
- ✅ `cosign verify` succeeds on original digest; output saved in submission
- ✅ `cosign verify` fails on tampered (re-tagged) image; output saved
- ✅ Original digest still verifies after the tamper attempt (defense-in-depth proof)
- ✅ "Why digest binding matters" answer demonstrates understanding of tag-mutation attack

### Task 2 (4 pts)
- ✅ SBOM attestation attached; `cosign verify-attestation --type cyclonedx` succeeds
- ✅ Decoded predicate matches Lab 4's SBOM (verified with diff)
- ✅ Provenance attestation attached; `cosign verify-attestation --type slsaprovenance` succeeds
- ✅ "Operational difference" answer concretely references the Log4Shell pattern

### Bonus Task (2 pts)
- ✅ `cosign verify-blob` succeeds on the original tarball
- ✅ `cosign verify-blob` fails on the tampered tarball
- ✅ Codecov 2021 mitigation answer correctly identifies the role of `cosign verify-blob`

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Sign + Tamper | **6** | Registry + signed image + verify pass + tamper fail + sanity recheck + digest-binding explanation |
| **Task 2** — Attestations | **4** | SBOM attest passes + provenance attest passes + Log4Shell operational answer |
| **Bonus Task** — Blob signing | **2** | sign-blob pass + verify-blob pass on original + fail on tampered + Codecov mapping |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Sigstore Cosign documentation](https://docs.sigstore.dev/cosign/system_config/specifications/) — Tool reference
- [in-toto Statement v1 spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) — Envelope shape
- [SLSA v1.0 Provenance predicate](https://slsa.dev/spec/v1.0/provenance) — What buildDefinition/runDetails should contain
- [CycloneDX attestation predicate type](https://cyclonedx.org/specification/overview/) — As used in `--type cyclonedx`
- [Distribution v3 documentation](https://distribution.github.io/distribution/) — The local registry image

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`cosign verify` fails with "unable to fetch image"** — make sure the registry is up: `docker ps | grep lab8-registry`. Also: Cosign expects HTTPS by default — for plain HTTP registries on localhost, add `--allow-http-registry` (Cosign 2.x).
- 🚨 **`cosign sign` succeeds but `cosign verify` fails** — typically a tag-vs-digest mismatch. Always use the `@sha256:...` digest, NOT the `:v20.0.0` tag, in both commands.
- 🚨 **`COSIGN_PASSWORD` env var ignored** — Cosign 2.x sometimes needs `--key cosign.key` with stdin: `COSIGN_PASSWORD=<your-pw> cosign sign ...`. Or unset password (insecure) with `cosign generate-key-pair --password ''`.
- 🚨 **Provenance attestation has empty `digest.sha256`** — the bash here extracts the digest from the file; check by `cat labs/lab8/results/juice-shop-digest.txt` first. The format is `localhost:5000/juice-shop@sha256:abc...` — extract just `abc...`.
- 🚨 **`cosign verify-attestation` succeeds but jq decoding fails** — Cosign output is line-delimited; pipe through `head -1 | jq` to handle multiple attestations.
- 💡 **gitleaks should block your `cosign.key` commit** (from Lab 3). If it doesn't, your pre-commit hook config is wrong. Re-run `pre-commit install` and verify by attempting `git add labs/lab8/keys/cosign.key && git commit`.

</details>

<details>
<summary>🪜 Looking ahead</summary>

- **Lab 9** (Falco + Conftest) — the verification step you ran here gets enforced at K8s admission time via Kyverno / Sigstore policy-controller
- **Lab 10** (DefectDojo) — your SBOM attestation can be downloaded + imported into DefectDojo at any future date; that's how a 2026 program responds when the next Log4Shell drops in 2027

</details>
