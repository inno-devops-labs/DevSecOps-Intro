# Lab 8 — Software Supply Chain Security: Submission


## Task 1 — Local registry, signing, verification, and tamper

Since port 5000 was used by the macOS, I further use port 5001.

### Evidence (digest references)

From `labs/lab8/analysis/ref.txt`:

- **Original signed image ref:** `localhost:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`

From `labs/lab8/analysis/ref-after-tamper.txt`:

- **After tamper ref:** `localhost:5001/juice-shop@sha256:50a3a2fef78c92dee45a3a9b72af5bdcbff6476e685cef49d97f286b6ce6f14a`


### How signing protects against tag tampering

Tag names like `localhost:5001/juice-shop:v19.0.0` are **mutable pointers**: anyone with push access can make `v19.0.0` refer to another manifest digest. Clients that only `docker pull` by tag cannot tell whether the content is still the image they expect.

**Image signing with Cosign fixes this in practice** when you **verify by digest** (as in this lab): the signature is associated with a specific `sha256:…` manifest. After the tamper step, **`cosign verify` fails** for the new digest (`REF_AFTER`) because that manifest was never signed with your key. The **old digest** (`REF`) still verifies, which is exactly how you preserve a trustworthy “known-good” identity for the artifact independent of tag games.

### What “subject digest” means

The **subject digest** is the cryptographic hash of the **container image manifest** (or, in other contexts, of the artifact) that the signature or attestation refers to. It uniquely identifies *this exact bits* in the registry. Changing the image changes the digest; the old signature does not “move” to the new digest automatically.

---

## Task 2 — Attestations (SBOM + provenance)

### How attestations differ from signatures

- A **signature** (Cosign on the image) answers: *“Was this exact image (digest) signed by this key?”* It does not, by itself, describe dependencies or how the image was built.
- An **attestation** is a **signed statement** (typically an [in-toto](https://github.com/in-toto/attestation) envelope) that binds **claims** about the subject to the same trust root: *predicate + subject digest + signature*. Examples: SBOM (what’s in the image) and provenance (how/when/by whom it was produced).

### SBOM attestation (CycloneDX)

The CycloneDX file `labs/lab8/attest/juice-shop.cdx.json` was attached with `cosign attest --type cyclonedx`. Verification output is in `labs/lab8/attest/verify-sbom-attestation.txt`.

Summary of the **verified predicate** (decoded from the attestation envelope with `jq` / scripting):

| Field | Value |
|--------|--------|
| Statement `_type` | `https://in-toto.io/Statement/v0.1` |
| `predicateType` | `https://cyclonedx.org/bom` |
| Subject | `localhost:5001/juice-shop` @ `sha256:872efcc0…00bd7` |
| `bomFormat` | CycloneDX |
| `specVersion` | 1.6 |
| **Component count** | **3532** |

So the SBOM attestation carries a **machine-readable inventory** (libraries, packages, metadata) for that digest, suitable for license, vulnerability, and supply-chain tooling—**in addition to** the plain image signature.

**Example `jq` inspection** of the CycloneDX file (counts and root component):

```bash
jq '{bomFormat, specVersion, serialNumber,
     root: .metadata.component | {name, version, type},
     components: (.components | length)}' \
  labs/lab8/attest/juice-shop.cdx.json
```

### Provenance attestation

The local predicate is in `labs/lab8/attest/provenance.json` (includes `_type` `https://slsa.dev/provenance/v1`, `buildType`, `builder.id`, invocation parameters with the image ref, and `buildStartedOn`). Verified output: `labs/lab8/attest/verify-provenance.txt`.

Decoded statement (from that file) includes:

- **Subject:** same `localhost:5001/juice-shop` digest `872efcc0…00bd7`
- **Predicate** documents a **manual local demo** build: who/what identifier (`student@local`), build type, parameters referencing the signed digest, and basic completeness flags with a timestamp.

**Why provenance matters for supply chain security:** it gives consumers **evidence about the build context** (who claimed to build it, when, and under what coarse description of the process). In real pipelines, provenance is used with policies (“only accept builds from CI service X”) and with SBOM/vuln data to reason about **trust and reproducibility**—not just “signed yes/no.”

**Note:** Cosign’s verified envelope reports `predicateType` `https://slsa.dev/provenance/v0.2` while the on-disk JSON uses the v1 `_type` URL. Practically, Cosign normalized the claim into the provenance format it attaches; verification succeeded against the intended image digest.

---

## Task 3 — Blob (tarball) signing

### Evidence

- `labs/lab8/artifacts/sample.tar.gz` — artifact  
- `labs/lab8/artifacts/sample.tar.gz.bundle` — Cosign bundle  
- `labs/lab8/artifacts/verify-blob.txt` contains: **`Verified OK`**

Sample payload (from `labs/lab8/artifacts/sample.txt`): timestamped line created at archive time for the lab tarball.

### Use cases for signing non-container artifacts

- **Release binaries** (CLI tools, firmware) so mirrors and users can detect tampering  
- **Configuration / policy bundles** (IaC archives, Helm packages, SBOM exports) distributed outside a registry  
- **Build intermediates** or evidence bundles where OCI image signing is not the right packaging model  

### How blob signing differs from image signing

Image signing references an **OCI image digest** in a **registry**; Cosign stores signatures/attestations in registry-specific ways. **Blob signing** operates on **arbitrary files** (here, `sample.tar.gz`) and uses a **bundle** (or detached material) so verifiers can check the file bytes against the signature. The trust model is similar (key material), but the **transport and artifact identity** are file-oriented rather than `registry/repo@sha256:…`.

