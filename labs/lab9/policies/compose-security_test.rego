package compose.security_test

import data.compose.security.deny
import data.compose.security.warn

test_hardened_compose_service_passes if {
  hardened := {
    "services": {
      "juice": {
        "image": "bkimminich/juice-shop:v19.0.0",
        "user": "65532:65532",
        "read_only": true,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
      },
    },
  }

  deny_result := deny with input as hardened
  warn_result := warn with input as hardened
  count(deny_result) == 0
  count(warn_result) == 0
}

test_compose_service_without_user_and_caps_fails if {
  insecure := {
    "services": {
      "juice": {
        "image": "bkimminich/juice-shop:v19.0.0",
        "read_only": false,
        "cap_drop": [],
        "security_opt": [],
      },
    },
  }

  deny_result := deny with input as insecure
  warn_result := warn with input as insecure
  count(deny_result) == 3
  count(warn_result) == 1
}

test_compose_service_cap_add_is_denied if {
  insecure_cap_add := {
    "services": {
      "juice": {
        "image": "bkimminich/juice-shop:v19.0.0",
        "user": "65532:65532",
        "read_only": true,
        "cap_drop": ["ALL"],
        "cap_add": ["SYS_ADMIN"],
        "security_opt": ["no-new-privileges:true"],
      },
    },
  }

  violations := deny with input as insecure_cap_add
  violations["service \"juice\" must not add capabilities"]
}

test_compose_service_named_user_is_accepted if {
  named_user := {
    "services": {
      "juice": {
        "image": "bkimminich/juice-shop:v19.0.0",
        "user": "appuser",
        "read_only": true,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
      },
    },
  }

  deny_result := deny with input as named_user
  warn_result := warn with input as named_user
  count(deny_result) == 0
  count(warn_result) == 0
}

test_compose_service_root_user_is_denied if {
  root_user := {
    "services": {
      "juice": {
        "image": "bkimminich/juice-shop:v19.0.0",
        "user": "root:root",
        "read_only": true,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
      },
    },
  }

  violations := deny with input as root_user
  violations["service \"juice\" must set an explicit non-root user"]
}
