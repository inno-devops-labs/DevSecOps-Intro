# Task 1

## Observations


Single understandable output and most interesting one:
```
[rightrat | ~/c/DevSecOps-Intro] docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
Events detected: 0
Rule counts by severity:
Events detected: 0
Rule counts by severity:
Triggered rules by rule name:
{"hostname":"571ea5bf0330","output":"2026-05-12T16:52:34.229939671+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/custom-rule.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=41575d6baa96 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"41575d6baa96","container.image.repository":"alpine","container.image.tag":"3.19","container.name":"lab9-helper","evt.arg.flags":"O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER","evt.time.iso8601":1778604754229939671,"fd.name":"/usr/local/bin/custom-rule.txt","k8s.ns.name":null,"k8s.pod.name":null,"user.name":"root"},"priority":"Warning","rule":"Write Binary Under UsrLocalBin","source":"syscall","tags":["compliance","container","drift"],"time":"2026-05-12T16:52:34.229939671Z"}
Triggered rules by rule name:
{"hostname":"571ea5bf0330","output":"2026-05-12T16:52:34.229939671+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/custom-rule.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=41575d6baa96 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"41575d6baa96","container.image.repository":"alpine","container.image.tag":"3.19","container.name":"lab9-helper","evt.arg.flags":"O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER","evt.time.iso8601":1778604754229939671,"fd.name":"/usr/local/bin/custom-rule.txt","k8s.ns.name":null,"k8s.pod.name":null,"user.name":"root"},"priority":"Warning","rule":"Write Binary Under UsrLocalBin","source":"syscall","tags":["compliance","container","drift"],"time":"2026-05-12T16:52:34.229939671Z"}
```
This triggered both the innate drift rule and my custom rule
My custom rule triggers on write to /usr/local/bin inside any container. Shouldn't trigger on writes to parental folders and cousin folders

## Test to find out whether the rule would trigger in subdirectories
```shell
[rightrat | ~/c/DevSecOps-Intro] docker exec --user 0 lab9-helper /bin/sh -lc 'mkdir /usr/local/bin/testdir'
[rightrat | ~/c/DevSecOps-Intro] docker exec --user 0 lab9-helper /bin/sh -lc 'echo blah blah > /usr/local/bin/testdir/test.txt'
{"hostname":"571ea5bf0330","output":"2026-05-12T17:01:04.341228872+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/testdir/test.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=41575d6baa96 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"41575d6baa96","container.image.repository":"alpine","container.image.tag":"3.19","container.name":"lab9-helper","evt.arg.flags":"O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER","evt.time.iso8601":1778605264341228872,"fd.name":"/usr/local/bin/testdir/test.txt","k8s.ns.name":null,"k8s.pod.name":null,"user.name":"root"},"priority":"Warning","rule":"Write Binary Under UsrLocalBin","source":"syscall","tags":["compliance","container","drift"],"time":"2026-05-12T17:01:04.341228872Z"}
{"hostname":"571ea5bf0330","output":"2026-05-12T17:01:04.341228872+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/testdir/test.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=41575d6baa96 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"41575d6baa96","container.image.repository":"alpine","container.image.tag":"3.19","container.name":"lab9-helper","evt.arg.flags":"O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER","evt.time.iso8601":1778605264341228872,"fd.name":"/usr/local/bin/testdir/test.txt","k8s.ns.name":null,"k8s.pod.name":null,"user.name":"root"},"priority":"Warning","rule":"Write Binary Under UsrLocalBin","source":"syscall","tags":["compliance","container","drift"],"time":"2026-05-12T17:01:04.341228872Z"}
```

# Task 2

## Unhardened manifest
```
[rightrat | ~/c/DevSecOps-Intro] docker run --rm -v "$(pwd)/labs/lab9":/project \
                                       openpolicyagent/conftest:latest \
                                       test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-unhardened.txt
WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

## Hardened manifest
```
[rightrat | ~/c/DevSecOps-Intro] docker run --rm -v "$(pwd)/labs/lab9":/project \
                                       openpolicyagent/conftest:latest \
                                       test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-hardened.txt


30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

## Docker Compose manifest
```
[rightrat | ~/c/DevSecOps-Intro] docker run --rm -v "$(pwd)/labs/lab9":/project \
                                       openpolicyagent/conftest:latest \
                                       test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-compose.txt

15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

Doesn't seem to check for everything