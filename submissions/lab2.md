## Task 1 — Baseline threat model

### Severity summary

| Severity  |  Count |
| --------- | -----: |
| critical  |      0 |
| high      |      0 |
| elevated  |      4 |
| medium    |     14 |
| low       |      5 |
| **Total** | **23** |

### Top five risks

| Severity | Rule ID                       | Technical asset | STRIDE                     | Why                                                                                                                                                                                                                      |
| -------- | ----------------------------- | --------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| elevated | `cross-site-scripting`        | `juice-shop`    | T — Tampering              | Cross-site scripting allows attacker-controlled script content to be injected into application responses and executed in a victim's browser, enabling modification of the content and behaviour presented to the victim. |
| elevated | `missing-authentication`      | `juice-shop`    | S — Spoofing               | Without authentication, an attacker may be able to access functionality without proving their identity and can potentially act as another user.                                                                          |
| elevated | `unencrypted-communication`   | `user-browser`  | I — Information Disclosure | Cleartext communication can expose transmitted data to an attacker who can observe the network traffic.                                                                                                                  |
| elevated | `unencrypted-communication`   | `reverse-proxy` | I — Information Disclosure | Unencrypted communication involving the reverse proxy can expose requests and responses to network attackers.                                                                                                            |
| medium   | `server-side-request-forgery` | `juice-shop`    | I — Information Disclosure | SSRF can allow an attacker to make the server access attacker-selected resources, potentially exposing internal services or sensitive information.                                                                       |

### Trust-boundary crossing

The Reverse Proxy → Juice Shop Application flow crosses the Container Network trust boundary shown in the DFD. The communication uses http in the baseline model, and the flow therefore carries traffic without transport encryption between the reverse proxy and the application. This makes the link an attractive target for an attacker who can gain access to or observe the container network, because the attacker could potentially intercept or manipulate application traffic. This flow is also directly related to the unencrypted-communication risk listed among the top five risks.

Another relevant crossing is the User Browser → Juice Shop Application flow. It crosses from the Internet into the Host and then reaches the application inside the Container Network, while also using http in the baseline model. Because the browser is externally controlled and the communication is cleartext, an attacker positioned on the network could potentially observe or modify requests and responses.
## Task 2 — Hardened threat model

### Security changes

The baseline model was copied to `threagile-model-secure.yaml` and hardened with three changes:

1. The direct Browser → Juice Shop communication link was changed from `http` to `https`.
2. The Reverse Proxy → Juice Shop communication link was changed from `http` to `https` and was given `token` authentication.
3. The Juice Shop Application and Persistent Storage assets were changed from `encryption: none` to `encryption: data-with-symmetric-shared-key`.

The Browser → Reverse Proxy link was already using HTTPS and therefore required no change.

### Baseline vs. secure severity counts

| Severity  | Baseline | Secure |  Delta |
| --------- | -------: | -----: | -----: |
| critical  |        0 |      0 |      0 |
| high      |        0 |      0 |      0 |
| elevated  |        4 |      1 |     -3 |
| medium    |       14 |     12 |     -2 |
| low       |        5 |      5 |      0 |
| **Total** |   **23** | **18** | **-5** |

The hardened model reduces the total number of risks from 23 to 18, a reduction of 5 risks, or approximately 21.7%.

### Removed rule IDs

The following rule IDs were present in the baseline model but no longer appear in the hardened model:

| Removed rule ID             | Model change that removed it                                                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `missing-authentication`    | Added `authentication: token` to the Reverse Proxy → Juice Shop communication link.                                                       |
| `unencrypted-communication` | Changed the Direct Browser → Juice Shop and Reverse Proxy → Juice Shop communication links from `http` to `https`.                        |
| `unencrypted-asset`         | Changed the Juice Shop Application and Persistent Storage assets from `encryption: none` to `encryption: data-with-symmetric-shared-key`. |

No new rule IDs appeared in the secure model.

### Remaining risks

The hardened model still produces 18 risks: 1 elevated, 12 medium, and 5 low. The remaining risks are mainly related to application-level behaviour and vulnerabilities that are not represented by transport encryption, authentication on the proxy-to-application link, or encryption at rest. These risks cannot all be removed by changing the YAML security properties of the communication links and assets; some require changes to the application's implementation, configuration, or deployment behaviour.

For example, cross-site scripting is an application-level risk and cannot be closed simply by changing a protocol or an encryption field in the Threagile model. Closing such a risk requires fixing the vulnerable application behaviour, such as validating and safely encoding untrusted input. Therefore, hardening the model reduces the attack surface but does not make the application risk-free.
