
# Lab 10 - Vulnerability Management: The Capstone
## Task 1

Defect Dojo version: 2.58.3

|parser|count|
|---|---|
|checkov scan | 80|
|kics scan | 10+6|
|anchore grype | 183|
|zap scan | 13|
|trivy scan | 177+87|
|semgrep json report | 27|


|severity|count|
|---|---|
|Critical |36|
|High     |253|
|Medium   |234|
|Low      |47|
|Info     |13|
|Total    |583|


CVE-2015-9235 Jsonwebtoken 0.1.0 is a one issue counted twice because it was caught by both trivy and trivy-image scans and they referred to exact same files. CVE-2018-16487 Lodash 2.4.2 is the same.


The most actionable are zap and semgrep findings. stuff like sql injection point at concrete source code and request paths that can be fixed. Grype, trivy and trivy-image scan the same base image, making duplicates and bloating the counts. Aside from that, most are from intentionally vulnerable node modules included with juice shop, which are legitimate risks, but zap and semgrep's application findings is a small set of unique directly exploitable.



## Task 2


|severity|default|mine|why|
|---|---|---|---|
|critical|7|2|a week is too long, repeated breaches can happen |
|high|30|7/28|for sprints|
|medium|90|60|for quarterly planning cycles |
|low|120|120|no need to bother too much with with those|



|parser|active|critical|high|medium|low|info|
|---|---|---|---|---|---|---|
|anchore grype|183|14|84|60|12|11|
|trivy scan|177|10|66|68|31|0|
|trivy image|76|10|66|0|0|0|
|semgrep|27|0|13|14|0|0|
|zap scan|13|0|2|4|3|4|
|checkov scan|80|0|0|80|0|0|
|kics ansible|10|0|9|0|1|0|
|kics palumi|6|1|2|1|0|2|
|total|583|36|253|234|47|13|

Median and oldest - 0 days because the findings dates are assigned on import, got with GET /api/v2/findings/?active=true&limit=1000 and jq '[.[].age]'. Share of active findings currently inside SLA: 97.7%, as the info ones dont have sla dates set. Aside from info its 100%. Query - jq '[.[] | select(.sla_days_remaining != null)] | length as $t | [.[] | select(.sla_days_remaining >= 0)] | length as $ok | ($ok/$t)*100'.

Labs 8 and 9 produced supply-chain signing, runtime detection, attestation, and policy-as-code evidence not represented in these scanner numbers, so they should be tracked as manual control evidence linked to same product and reviewed during release readiness.

GHSA-p6mc-m468-83gw in lodash.set:4.3.2 until 2026-12-25. Its high without fix available, its going to be monitored until upstream publishes a fix.

583 findings, 36 critical, not good standings. More than half of them is dependency based and duplicated but still plusungood. The biggest risk is of course the sql injections, recognized statically and dynamically. Closing it requires a weekly remediation queue and tracking for labs 8 and 9 controls that do not enter dd.

