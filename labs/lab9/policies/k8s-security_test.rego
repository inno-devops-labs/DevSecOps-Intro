package k8s.security_test

import data.k8s.security.deny
import data.k8s.security.warn

test_hardened_deployment_passes if {
  hardened := {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "seccompProfile": {"type": "RuntimeDefault"},
          },
          "initContainers": [
            {
              "name": "prepare-juice-shop-root",
              "image": "bkimminich/juice-shop:v19.0.0",
              "securityContext": {
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": {
                  "drop": ["ALL"],
                },
              },
              "resources": {
                "requests": {"cpu": "25m", "memory": "64Mi"},
                "limits": {"cpu": "100m", "memory": "128Mi"},
              },
            },
          ],
          "containers": [
            {
              "name": "juice",
              "image": "bkimminich/juice-shop:v19.0.0",
              "securityContext": {
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": {
                  "drop": ["ALL"],
                },
              },
              "resources": {
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
              },
              "readinessProbe": {"httpGet": {"path": "/", "port": 3000}},
              "livenessProbe": {"httpGet": {"path": "/", "port": 3000}},
            },
          ],
        },
      },
    },
  }

  deny_result := deny with input as hardened
  warn_result := warn with input as hardened
  count(deny_result) == 0
  count(warn_result) == 0
}

test_unhardened_deployment_fails_expected_rules if {
  unhardened := {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "juice",
              "image": "bkimminich/juice-shop:latest",
            },
          ],
        },
      },
    },
  }

  violations := deny with input as unhardened
  violations["container \"juice\" uses disallowed :latest tag"]
  violations["container \"juice\" must set runAsNonRoot: true"]
  violations["container \"juice\" must set allowPrivilegeEscalation: false"]
  violations["container \"juice\" must set readOnlyRootFilesystem: true"]
  violations["container \"juice\" must drop ALL capabilities"]
  violations["container \"juice\" must set seccompProfile.type to RuntimeDefault or Localhost"]
  violations["container \"juice\" missing resources.requests.cpu"]
  violations["container \"juice\" missing resources.requests.memory"]
  violations["container \"juice\" missing resources.limits.cpu"]
  violations["container \"juice\" missing resources.limits.memory"]
  warn_result := warn with input as unhardened
  count(warn_result) == 2
}

test_insecure_init_container_fails_expected_rules if {
  insecure_init := {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "initContainers": [
            {
              "name": "prepare",
              "image": "busybox:latest",
            },
          ],
          "containers": [
            {
              "name": "juice",
              "image": "bkimminich/juice-shop:v19.0.0",
              "securityContext": {
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": {
                  "drop": ["ALL"],
                },
              },
              "resources": {
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
              },
              "readinessProbe": {"httpGet": {"path": "/", "port": 3000}},
              "livenessProbe": {"httpGet": {"path": "/", "port": 3000}},
            },
          ],
        },
      },
    },
  }

  violations := deny with input as insecure_init
  violations["container \"prepare\" uses disallowed :latest tag"]
  violations["container \"prepare\" must set runAsNonRoot: true"]
  violations["container \"prepare\" must set allowPrivilegeEscalation: false"]
  violations["container \"prepare\" must set readOnlyRootFilesystem: true"]
  violations["container \"prepare\" must drop ALL capabilities"]
  violations["container \"prepare\" must set seccompProfile.type to RuntimeDefault or Localhost"]
  violations["container \"prepare\" missing resources.requests.cpu"]
  violations["container \"prepare\" missing resources.requests.memory"]
  violations["container \"prepare\" missing resources.limits.cpu"]
  violations["container \"prepare\" missing resources.limits.memory"]
}

test_container_capabilities_add_is_denied if {
  insecure_caps := {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "seccompProfile": {"type": "RuntimeDefault"},
          },
          "containers": [
            {
              "name": "juice",
              "image": "bkimminich/juice-shop:v19.0.0",
              "securityContext": {
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": {
                  "drop": ["ALL"],
                  "add": ["SYS_ADMIN"],
                },
              },
              "resources": {
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
              },
              "readinessProbe": {"httpGet": {"path": "/", "port": 3000}},
              "livenessProbe": {"httpGet": {"path": "/", "port": 3000}},
            },
          ],
        },
      },
    },
  }

  violations := deny with input as insecure_caps
  violations["container \"juice\" must not add capabilities"]
}

test_pod_level_run_as_non_root_is_accepted if {
  pod_level := {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "runAsNonRoot": true,
            "seccompProfile": {"type": "RuntimeDefault"},
          },
          "containers": [
            {
              "name": "juice",
              "image": "bkimminich/juice-shop:v19.0.0",
              "securityContext": {
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": {
                  "drop": ["ALL"],
                },
              },
              "resources": {
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
              },
              "readinessProbe": {"httpGet": {"path": "/", "port": 3000}},
              "livenessProbe": {"httpGet": {"path": "/", "port": 3000}},
            },
          ],
        },
      },
    },
  }

  deny_result := deny with input as pod_level
  warn_result := warn with input as pod_level
  count(deny_result) == 0
  count(warn_result) == 0
}
