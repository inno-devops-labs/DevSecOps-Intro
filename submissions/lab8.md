# Lab 8 — Submission

> **Tooling note:** This lab was completed with **Cosign v3.1.1** (the lab targets v2.4.x). v3 changed transparency-log opt-out: `--tlog-upload=false` now conflicts with the new signing-config system, so keyed signing without Rekor uses `COSIGN_EXPERIMENTAL=0` on sign/attest and `--insecure-ignore-tlog` on verify. The local registry runs on **port 5001**, not 5000, because macOS AirPlay Receiver (AirTunes) occupies port 5000 and returns 403 on all requests.

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001` (registry:3 / Distribution v3)
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest (the registry re-computed a single-platform digest on push, distinct from the upstream multi-arch digest `fd58bdc9…`):
```
localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Signing
```
COSIGN_PASSWORD="" COSIGN_EXPERIMENTAL=0 cosign sign \
  --key labs/lab8/keys/cosign.key --allow-http-registry --yes "$DIGEST"
Signing artifact... | Pushing signature to: localhost:5001/juice-shop
```

### Verification (PASSED)
```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": {}
  }
]
```
All three checks passed: cosign claims validated, existence verified offline, signature verified against the public key.

### Tamper Demo (FAILED — correctly)
Re-tagged `alpine:3.20` as `localhost:5001/juice-shop:v20.0.0-tampered` and pushed it. The registry assigned it a different digest (`sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d`). Verifying that digest:
```
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
After the tamper attempt, the original digest still verifies cleanly:
```
sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign bound the signature to the image's content digest (`sha256:cbdfc00…`), not to the mutable `:v20.0.0` tag. The tamper attempt re-pointed a tag at a completely different image (alpine), which necessarily has a different digest, so verification found no signature covering those bytes and failed. If Cosign had signed the tag instead of the digest, an attacker who can push to the registry could move the tag to point at a malicious image while the signature "for that tag" still appeared valid — the classic tag-mutation attack. Digest binding makes the signature cover exactly the bytes that were reviewed, and nothing else.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- The Lab 4 CycloneDX SBOM (CycloneDX 1.6, 3068 components) was attached as the predicate and verified with `cosign verify-attestation --type cyclonedx`.
- Component count round-trip:
```
Lab 4 source:      3068
From attestation:  3068
```
The decoded predicate extracted from the attestation matches the Lab 4 source SBOM exactly — the SBOM survived the in-toto envelope + DSSE signing + registry round-trip intact.

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance` exit 0, verified)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- Verified predicate:
```json
{
  "buildType": "https://example.com/lab8/local-build",
  "builder": {
    "id": "https://localhost/lab8-student"
  },
  "invocation": {
    "configSource": {
      "digest": { "sha1": "abc123" },
      "uri": "https://github.com/jestersw/DevSecOps-Intro"
    }
  }
}
```

### What this gives a Lab 9 verifier
A "signed but no SBOM" image proves *who* built it and *that it wasn't tampered with*, but says nothing about *what's inside*. A "signed with SBOM" image proves both — the signature guarantees the SBOM is the authentic inventory for exactly this digest. When the next Log4Shell drops, the operational difference is enormous: with the SBOM attestation, a Kyverno/Sigstore admission policy (Lecture 9 slide 4) can require the SBOM predicate at deploy time, and an operator can query every running image's attested SBOM to answer "are we exposed?" in minutes — without re-scanning or re-pulling anything. Without it, the team is back to manually inspecting each image under time pressure while the exploit is already in the wild. The SBOM turns incident response from archaeology into a database query.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` → produced `my-tool.tar.gz.bundle`
- Copied the tarball, bundle, and public key to a fresh directory (simulating a download) and verified:
```
Verified OK
```

### Tamper test failed (correctly)
Appended `MALICIOUS PAYLOAD` to the downloaded tarball, then re-verified:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: ...
```

### Codecov 2021 mitigation
Codecov's Bash Uploader was distributed via `curl | bash` with no integrity check, so when an attacker modified the hosted script (harvesting CI environment secrets), every consumer silently ran the trojanized version. If consumers had run `cosign verify-blob --key <codecov-pub> --bundle uploader.sig codecov-uploader.sh` before piping it to `bash`, the check would have failed the instant the script's bytes differed from what Codecov signed — exactly like our tamper test above returned "invalid signature" for the one-line modification. The `curl | bash` pattern's fatal flaw is that it couples download and execution with no verification gate in between; `cosign verify-blob` inserts that gate, binding trust to the signed byte stream rather than to whatever the server happens to serve at download time (Lecture 8 slide 14).
