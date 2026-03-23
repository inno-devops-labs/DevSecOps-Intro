# Container Security Analysis Report

## 1. Top 5 Critical/High Vulnerabilities

  ------------------------------------------------------------------------
  CVE ID           Package           Severity             Impact
  ---------------- ----------------- -------------------- ----------------
  CVE-2025-69421   openssl/libssl3   High                 TLS security
                                                          compromise,
                                                          potential MITM
                                                          attacks

  N/A (Race        node@22.18.0      Critical             Can lead to
  Condition)                                              unpredictable
                                                          behavior and
                                                          potential
                                                          privilege
                                                          escalation

  N/A (Symlink     node@22.18.0      High                 File overwrite
  Following)                                              or unauthorized
                                                          file access

  N/A (Uncaught    node@22.18.0      High                 Application
  Exception)                                              crash → DoS

  N/A (Undefined   node@22.18.0      High                 Unexpected
  Behavior)                                               execution paths,
                                                          potential
                                                          exploitation
  ------------------------------------------------------------------------

------------------------------------------------------------------------

## 2. Dockle Configuration Findings

### WARN / INFO Issues

-   Missing HEALTHCHECK\
    → Containers may run in broken state without detection.

-   Content trust disabled\
    → Risk of pulling tampered images.

-   Unnecessary files (.DS_Store)\
    → Increases attack surface and image size.

### Why this matters

These issues reduce visibility, increase supply chain risk, and expose
unnecessary artifacts attackers can exploit.

------------------------------------------------------------------------

## 3. Security Posture Assessment

-   Runs as root: Likely YES (distroless default unless specified)
-   Issues:
    -   Large number of vulnerabilities (65 High, 11 Critical)
    -   No health monitoring
    -   No enforced non-root user

### Recommendations

-   Upgrade Node.js to 22.22.0+
-   Upgrade OpenSSL
-   Add USER directive
-   Add HEALTHCHECK
-   Enable Docker Content Trust
-   Remove unnecessary files

------------------------------------------------------------------------

## 4. Configuration Comparison

  Setting        Default     Hardened            Production
  -------------- ----------- ------------------- --------------------------------
  Capabilities   None        ALL dropped         ALL dropped + NET_BIND_SERVICE
  Security Opt   None        no-new-privileges   no-new-privileges
  Memory         Unlimited   512MB               512MB
  CPU            Unlimited   Unlimited           Unlimited
  PIDs           Unlimited   Unlimited           100
  Restart        No          No                  on-failure

------------------------------------------------------------------------

## 5. Security Measures Analysis

### Capabilities

Linux capabilities split root privileges into smaller units.

-   Dropping ALL: → Prevents privilege escalation and kernel-level
    attacks

-   Adding NET_BIND_SERVICE: → Allows binding to ports \<1024

Trade-off: minimal required privileges vs functionality.

------------------------------------------------------------------------

### no-new-privileges

Prevents processes from gaining additional privileges.

-   Stops privilege escalation exploits
-   Downside: may break apps needing privilege escalation

------------------------------------------------------------------------

### Resource Limits

Without limits: - Containers can exhaust host resources (DoS)

Memory limit: - Prevents memory exhaustion attacks

Risk: - Too low → app crashes

------------------------------------------------------------------------

### PIDs Limit

-   Prevents fork bombs (infinite process spawning)

Right value: - Based on expected workload

------------------------------------------------------------------------

### Restart Policy

-   on-failure: → Restarts container only on crashes

Comparison: - always → may restart compromised container endlessly

------------------------------------------------------------------------

## 6. Critical Thinking

### Development Profile

Default: - Easier debugging - No restrictions

### Production Profile

Production: - Strong isolation - Resource control - Restart resilience

------------------------------------------------------------------------

### Real-world problem solved

Prevents: - Resource exhaustion - Container escape - Privilege
escalation

------------------------------------------------------------------------

### Attack Differences

Production blocks: - Privilege escalation - Fork bombs - Resource abuse

------------------------------------------------------------------------

### Additional Hardening

-   Read-only filesystem
-   Seccomp profile
-   AppArmor/SELinux
-   Non-root user
-   Network policies

------------------------------------------------------------------------

## Conclusion

The production configuration significantly improves security by reducing
privileges, enforcing limits, and improving resilience. However,
vulnerabilities in dependencies remain the biggest risk and must be
addressed via updates.
