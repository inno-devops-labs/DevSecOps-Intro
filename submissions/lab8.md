# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: 
```
sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face
```

### Signing
- Output of `cosign sign` (just the success line is fine):
```
Signing artifact... Pushing signature to: 127.0.0.1:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"image":{"docker-manifest-digest":"sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}},{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"image":{"docker-manifest-digest":"sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"image":{"docker-manifest-digest":"sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}},{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"image":{"docker-manifest-digest":"sha256:fd6c17a1107fecff137b75d1fd8481b64d0c44370790ad78bc39107aac86face"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)

If Cosign had signed the tag instead of the digest, the signature would have been bound to the mutable tag name (juice-shop:v20.0.0) rather than the immutable content hash. This would have allowed an attacker to retag a malicious image (like the fake Alpine image) with the same tag, and the signature would still appear valid because it only verifies the tag name, not the actual content. Signing the digest ensures that the signature is cryptographically bound to the exact image contents, making tampering impossible without invalidating the signature.