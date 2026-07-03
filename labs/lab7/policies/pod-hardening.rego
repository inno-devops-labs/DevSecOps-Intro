package main

# Ожидаемый путь к спеке пода внутри Deployment
pod_spec := input.spec.template.spec

# 1. Pod-level: runAsNonRoot должен быть true
deny[msg] {
    input.kind == "Deployment"
    not pod_spec.securityContext.runAsNonRoot == true
    msg := sprintf("%s: pod securityContext.runAsNonRoot must be true", [input.metadata.name])
}

# 2. Container-level: readOnlyRootFilesystem должен быть true у КАЖДОГО контейнера
deny[msg] {
    input.kind == "Deployment"
    container := pod_spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("%s: container '%s' must set securityContext.readOnlyRootFilesystem = true", [input.metadata.name, container.name])
}

# 3. Container-level: allowPrivilegeEscalation должен быть false у КАЖДОГО контейнера
deny[msg] {
    input.kind == "Deployment"
    container := pod_spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("%s: container '%s' must set securityContext.allowPrivilegeEscalation = false", [input.metadata.name, container.name])
}

# 4. Container-level: capabilities.drop должен содержать "ALL"
deny[msg] {
    input.kind == "Deployment"
    container := pod_spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("%s: container '%s' must drop ALL capabilities (securityContext.capabilities.drop = [\"ALL\"])", [input.metadata.name, container.name])
}

# 5. (доп. страховка) securityContext вообще отсутствует у контейнера
deny[msg] {
    input.kind == "Deployment"
    container := pod_spec.containers[_]
    not container.securityContext
    msg := sprintf("%s: container '%s' has no securityContext defined at all", [input.metadata.name, container.name])
}
