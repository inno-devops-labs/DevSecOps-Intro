# Lab 8 — Submission

Supply-chain signing on Juice Shop (`bkimminich/juice-shop:v20.0.0`) with Cosign in a local registry:
keyed image signing + tamper demo, SBOM + provenance attestations, and blob signing.

Tooling: Cosign v3.1.1 · Docker 29.4.0 · registry:3 (Distribution v3) · jq 1.7.1.

> Two small environment notes (both harmless, just so the commands match the outputs):
> - **Registry port 5001, not 5000.** On macOS the AirPlay Receiver (ControlCenter) already listens on
>   port 5000 and answers with `403 AirTunes`, which blocks Cosign. I ran the registry on `localhost:5001`.
> - **Cosign v3 flags.** The lab was written for Cosign v2. In v3, disabling the transparency log for local
>   keyed signing needs `--use-signing-config=false --tlog-upload=false`, and plain-HTTP registries need
>   `--allow-http-registry`. Verify uses `--insecure-ignore-tlog` as documented.

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001` (registry:3)
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest: `localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

(The registry stores a single-platform manifest, so its digest `cbdfc00d…` differs from Docker Hub's
multi-arch index digest `fd58…` — I signed the digest the registry actually serves.)

### Signing
```
$ COSIGN_PASSWORD=*** cosign sign --key labs/lab8/keys/cosign.key \
    --use-signing-config=false --tlog-upload=false --allow-http-registry --yes "$DIGEST"
Signing artifact...
Pushing signature to: localhost:5001/juice-shop
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

### Tamper Demo (FAILED — correctly)
Re-tagged `alpine:3.20` as `localhost:5001/juice-shop:v20.0.0-tampered` (digest
`sha256:45e09956…`) and verified it:
```
Error: no signatures found
error during command execution: no signatures found
```
Exit code 10 — the signature does not exist for alpine's digest.

### Sanity — original still verifies
```
$ cosign verify --key cosign.pub --insecure-ignore-tlog --allow-http-registry "$DIGEST"
# exit 0 — docker-manifest-digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Why digest binding matters (Lecture 8 slide 6)
The signature is bound to the image **digest** (`sha256:cbdfc00d…`), which is the hash of the content
itself — change one byte and the digest changes. The tamper attempt reused the *tag* `v20.0.0-tampered`
but pointed it at alpine, a different digest, so verification found no signature for that content. If
Cosign had signed the **tag** instead, an attacker could re-point `:v20.0.0` at a malicious image and the
signature would still "match" the tag name — exactly the mutable-tag attack digest binding prevents.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0), predicate = Lab 4's `juice-shop.cdx.json`
- Decoded statement (verify-attestation):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    { "name": "localhost:5001/juice-shop",
      "digest": { "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113" } }
  ],
  "predicate": { "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [ ...3068 items... ] }
}
```
- Component count matches Lab 4 source: **yes** (3068 == 3068)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: **empty** (identical)

### Provenance attestation
- Attached: yes (`cosign verify-attestation --type slsaprovenance` exit 0)
- predicateType: `https://slsa.dev/provenance/v0.2`
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier
A "signed but no SBOM" image proves *who built it*, but a Kyverno / policy-controller admission rule
can only answer "is this from a trusted signer?" A "signed with SBOM" image lets the same admission
policy also require the CycloneDX predicate, so when the next Log4Shell drops the cluster can be queried
offline — "which running images contain log4j-core?" — straight from the attested SBOM, with no image
re-scan and a signed guarantee the inventory matches the exact digest deployed. That's the difference
between "we think we're affected" and "we know, and can prove it."

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle` (`cosign sign-blob --bundle`)
- Verify-blob success output:
```
$ cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle --insecure-ignore-tlog my-tool.tar.gz
Verified OK
```

### Tamper test failed (correctly)
Appended `MALICIOUS PAYLOAD` to the tarball and re-verified:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature ...
```
Exit code 1 — the signature is bound to the original byte stream.

### Codecov 2021 mitigation
Codecov's bash uploader was shipped via `curl | bash` with no integrity check, so when the attacker
modified the script the consumers ran it blindly. If each CI consumer had run
`cosign verify-blob --key <codecov-pub> --bundle uploader.bundle uploader.sh` before `bash`-ing it, the
modified bytes would have produced exactly the failure above ("invalid signature"), the verify step would
have exited non-zero, and the pipeline would have refused to run the tampered script (Lecture 8 slide 14).
Signing the *artifact bytes* is what closes the `curl | bash` gap.
