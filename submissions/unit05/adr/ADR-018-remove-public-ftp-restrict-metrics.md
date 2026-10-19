# ADR-018: Remove public file listing and restrict operational metrics

- **Status:** Proposed pending local route/configuration validation
- **Context:** Threats T-13 and T-15; F1 crosses TB-1 → TB-4. Public file-serving paths may expose backups or unintended artifacts, while metrics may reveal internal runtime information.
- **Decision:** Remove an unnecessary public `/ftp` route. If files are required, store them behind the intended authentication and authorization path. Restrict `/metrics` to internal monitoring or authenticated operators.
- **Alternatives rejected:** Disabling directory listing alone may leave guessable files reachable. Obscuring the metrics URL is not access control.
- **Consequences accepted:** Existing links or support workflows may need updating. Monitoring must use an allowed internal path.
- **Validation:** On the local target, `/ftp` should return 404 after removal and an external request to `/metrics` should be denied or unreachable after restriction. Capture the actual responses; do not rely on the worked example’s status codes.
- **Residual risk:** Previously copied or indexed files may remain exposed elsewhere, and a misconfigured monitoring ingress could re-expose metrics. Owner: application maintainer. Review after route/configuration changes.
