# Lab 7 - Container and Kubernetes Hardening

## Task 1

|Vulneratbility|trivy|grype|
|---|---|---|
|Critical|11|14|
|High|76|85|
|Total|87|99|

They're different because they use different databases and matching rules, and Grype reports both CVE and GHSA identifiers for the same package. Neither one better, but overlap matters


|severity|id|package|ver|
|---|---|---|---|
|CRITICAL       | CVE-2023-46233 | crypto-js |3.3.0 -> 4.2.0|
|CRITICAL       | CVE-2026-71851 | crypto-js |3.3.0 -> 4.0.0|
|CRITICAL       | CVE-2015-9235  | jsonwebtoken |0.1.0 -> 4.2.2|
|CRITICAL       | CVE-2015-9235  | jsonwebtoken |0.4.0 -> 4.2.2|
|CRITICAL       | CVE-2019-10744 | lodash |2.4.2 -> 4.17.12|
|CRITICAL       | CVE-2026-59873 | tar |4.4.19 -> 7.5.19|
|CRITICAL       | CVE-2026-59873 | tar |6.2.1 -> 7.5.19|
|CRITICAL       | CVE-2026-59873 | tar |7.5.15 -> 7.5.19|
|HIGH   | CVE-2026-14456 | libssl3t64 |3.5.5-1~deb13u2 -> 3.5.7-1~deb13u2|
|HIGH   | CVE-2026-45447 | libssl3t64 |3.5.5-1~deb13u2 -> 3.5.6-1~deb13u2|



|code|severity|desc|what it allows|
|---|---|---|---|
|DS-0002 |HIGH| Last USER command in Dockerfile should not be 'root'|      The container runs as root, so any RCE is root, one kernel or runtime bug away from a host escape, and root can write anywhere in the image. |
|DS-0001 |MEDIUM| Specify a tag in the 'FROM' statement for image 'node'|  Latest node goes in the build without checks, could be compromised|
|DS-0004 |MEDIUM| Port 22 should not be exposed in Dockerfile|             An SSH daemon is a second entry path that bypasses the orchestrator's access model| 
|DS-0026 |LOW| Add HEALTHCHECK instruction in your Dockerfile|             The runtime cannot tell a wedged container from a healthy one, so a crashed process keeps receiving traffic instead of being restarted, and masks an attacker who has killed the app |


The correct action is to reduce reachability and blast radius: confirm whether the vulnerable code path is invoked, if it is, pin a patched fork or vendor the one function, drop the dependency, or put a control in front of the exposure, track with an owner and a re-scan cadence so the day a fix lands it becomes a normal ticket. 

What I tell a manager asking why the number is not zero:  it is not achievable while upstream has no patch. 
The honest metric is known criticals with an available fix still unshipped.
Criticals without fix are managed with compensating controls and accept with eyes open.


## Task 2

Namespace labels & security contexts:

```yaml
pod-security.kubernetes.io/enforce: restricted      
pod-security.kubernetes.io/warn:    restricted 
pod-security.kubernetes.io/audit:   restricted 
```


```yaml
runAsNonRoot: true
runAsUser: 65532           
runAsGroup: 65532
fsGroup: 65532             
seccompProfile: { type: RuntimeDefault }
```

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true    
capabilities: { drop: ["ALL"] }
```


Proof:
```
kubectl -n juice-shop get pods -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-69cd46985d-tt5dw   1/1     Running   0          53s


kubectl -n juice-shop exec <pod> -c juice-shop -- /nodejs/bin/node -e 'console.log(process.getuid())'
65532
```


Comparison:
||unhardened|restricted|
|---|---|---|
|Vulnerabilities | 11+74 | 11+74 |
|Misconfigurations | 0+3 | 0+1|
|Secrets| 0+2 | 0+2 |


Hardening is a property of image running. The CVEs are the same no matter the config, a package upgrade changes that. 
The misconfigurations are read off the pod spec, so they move: the plain deployment has `KSV-0014` and two `KSV-0118`, 
the hardened one clears `KSV-0118`s and is left with `KSV-0014`. The two secrets are also image content, so they appear in both.




Blocked by restricted: the default container security context. Restricted rejected deployment with no securityContext at admission

Added without requirements: a network policy that default-denies both directions for the app pod and re-opens only ingress to :3000 and egress for DNS to kube-system.


## Bonus

```
C /juice-shop/frontend/dist  
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/ftp            
A /juice-shop/ftp/legal.md
C /juice-shop/data           
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/i18n           
A /juice-shop/i18n/<44 translation json files>
C /juice-shop/logs
```


| Volume | at | Why |
|---|---|---|
| `data` | `/juice-shop/data`  | writes `juiceshop.sqlite`, but the dir also ships `data/static/` which `datacreator` reads at startup |
| `dist` | `/juice-shop/frontend/dist` | writes `owasp_promo.vtt`, but the dir is the served Angular app |
| `wellknown` | `/juice-shop/.well-known` | writes `csaf/provider-metadata.json`, but ships `csaf/`, `security.txt` |
| `ftp` | `/juice-shop/ftp` | only receives `legal.md` at startup|
| `logs` | `/juice-shop/logs` | runtime logs|
| `i18n` | `/juice-shop/i18n`  | ships only `.gitkeep` |
| `tmp` | `/tmp` | scratch |



`data`, `frontend/dist` and `.well-known` each ship files that are read or served
at runtime, so mounting an empty volume over any of them hides those files and the app either exits
or serves a blank page. The fix is an initContainer that seeds the volumes before the main container
starts. Because the image is distroless, the seeding is done with Node

```
initContainers:
  - name: seed-writable-dirs
    image: <same digest>
    command: ["/nodejs/bin/node", "-e", "
      const fs=require('fs');
      fs.cpSync('/juice-shop/data','/seed/data',{recursive:true});
      fs.cpSync('/juice-shop/frontend/dist','/seed/dist',{recursive:true});
      fs.cpSync('/juice-shop/.well-known','/seed/wellknown',{recursive:true});"]
    volumeMounts:
      - { name: data, mountPath: /seed/data }
      - { name: dist, mountPath: /seed/dist }
      - { name: wellknown, mountPath: /seed/wellknown }
```


```
kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-69cd46985d-tt5dw   1/1     Running   0          47s
```
```
kubectl -n juice-shop get pod <pod> -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'
kubectl -n juice-shop port-forward deploy/juice-shop 3000:3000 & curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/
curl -s http://127.0.0.1:3000/rest/admin/application-version
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/main.js
true
HTTP 200
{"version":"20.0.0"}
HTTP 200
```