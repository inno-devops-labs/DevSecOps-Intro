## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|-------|
| Critical | <0>    |
| High |<0> | 
| Elevated | <4> | 
| Medium | <14> | 
| Low | <5> | 
| **Total** | <23> | 

### Top 5 risks
1. **<missing-authentication>** - <Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application>; severity <elevated>; affecting <juice-shop>
2. **<cross-site-scripting>** - <Cross-Site Scripting (XSS) risk at Juice Shop Application>; severity <elevated>; affecting <juice-shop>
3. **<unencrypted-communication>** - <Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.)>; severity <elevated>; affecting <user-browser>
4. **<unecrypted-communication>** - <Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application>; severity <elevated>; affecting <reverse-proxy>
5. **<unnecessary-data-transfer>** - <Unnecessary Data Transfers of Tokens & Sessions data at User Browser from/to Juice Shop Application>; severity <low>; affecting<user-browser>

### STRIDE mapping
- Risk 1: **<S/E>** - <attacker can impersonate components and gain privileges>
- Rick 2: **<I/E>** - <XSS can steal user data and be executed with another privileges>
- Risk 3: **<I>** - <attacker can steal user data(no encryption)>
- Risk 4: **<I>** - <attacker can read all traffic between reverse proxy to application>
- Risk 5: **<T/E>** - <attacker can modify backdoored container base image>

### Trust boundary observation
Direct arrow from User Browser to Juice Shop Application appears in the top-5 risks(risk 4). Arrow is particularly attractive to an attacker(it is easy to steal sensitive data)

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | <0> | <0> | <0> |
| High | <0> | <0> | <0> |
| Elevated | <4> | <2> | <-2> |
| Medium | <14> | <13> | <-1> |
| Low | <5> | <5> | <0> |
| **Total** | <23> | <20> | <-3> |

## Which rules are GONE in the secure variant?

1. **`unencrypted-communication@user-browser→direct-to-app-no-proxy`** — fixed by `protocol: https`
2. **`unencrypted-communication@reverse-proxy→to-app`** — fixed by `protocol: https`
3. **`unencrypted-asset@persistent-storage`** — fixed by `encryption: data-with-symmetric-shared-key`

## Which rules are STILL THERE in the secure variant?

1. **`missing-authentication@reverse-proxy→to-app`** — HTTPS provides encryption, not authentication. The proxy still doesn't prove its identity to the app.

2. **`container-baseimage-backdooring@juice-shop`** — Your changes target runtime controls. The container supply chain (base image source, signing) remains unaddressed.

## Honesty check

**No** — drop was 3/23 risks (13%), not >50%. Encryption fixes are cheap config changes, but they only address 13% of risks. The remaining 87% require deeper architectural changes (auth, supply chain, input validation) costing 10-100x more.
