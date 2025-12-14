## Task 1

### Risk Ranking

Upon activation `threagile` produced a .pdf report along with two diagrams and more detailed .json files.

![data-asset-diagram](https://i.ibb.co/XxBx55MT/data-asset-diagram.png)

![data-flow-diagram](https://i.ibb.co/fVdYL68L/data-flow-diagram.png)

Below is the evaluation and explanation of top 5 risks identified from the produced report.

> Composite risk score is evaluated as $\text{severity} \cdot 100 + \text{likelihood} \cdot 10 + \text{impact}$

| Priority | Category                     | Asset                  | Severity       | Likelihood        | Impact       | Composite Score |
| -------- | ---------------------------- | ---------------------- | -------------- | ----------------- | ------------ | --------------- |
| 1        | `unencrypted-communication`  | `user-browser`         | elevated ($4$) | likely ($3$)      | high ($3$)   | $433$           |
| 2        | `missing-authentication`     | `juice-shop` (backend) | elevated ($4$) | likely ($3$)      | medium ($2$) | $432$           |
| 3        | `unencrypted-communication`  | `reverse-proxy`        | elevated ($4$) | likely ($3$)      | medium ($2$) | $432$           |
| 4        | `cross-site-scripting`       | `juice-shop` (backend) | elevated ($4$) | likely ($3$)      | medium ($2$) | $432$           |
| 5        | `cross-site-request-forgery` | `juice-shop` (backend) | medium ($2$)   | very-likely ($4$) | low ($1$)    | $241$           |

### 1. Unencrypted frontend-backend communication

The user browser is allowed to make requests directly to frontend, bypassing the secure proxy. This setup neglects any security measures enabled by the proxy and allows plain HTTP connection without any encryption or security headers, thus subjecting the user-app communication to the risk of full compromise of confidentiality and integrity.

### 2. Blind backend-proxy communication

The juice shop backend enforces neither encryption nor authentication when communicating with the reverse proxy, enabling any other compromised component within the system to impersonate the proxy or even manipulate the legitimate proxy traffic.

### 3. Unprotected proxy-backend communication

The internal reverse proxy responds to backend over an unencrypted channel. Thus, if an attacker manages to compromise the host, it would be easy to observe and manipulate the traffic. This kind of compromise would expose critical user data, resulting in session hijacking.

### 4. Untrusted data mishandling

Juice shop frontend renders several untrusted data assets, such as accounts, orders, catalog, and comments. Lack of proper protections when rendering untrusted data enables attackers to target the users with XSS injections.

### 5. Relaxed cookie handling policy

Juice shop backend exposes several plain HTTP endpoints that affect sensitive data. Given the cookie and anti-CSRF configurations aren't cautious enough, the user browsers can be manipulated to send unintended authenticated requests, affecting sensitive data.
