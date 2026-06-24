package authz

import future.keywords.if
import future.keywords.in

# Default is always DENY
default allow = false

# Rule 1: patient-service can read patients
allow if {
    input.service == "patient-service"
    input.action == "read:patients"
}

# Rule 2: admin-service can do everything
allow if {
    input.service == "admin-service"
    input.action in ["read:patients", "write:patients", "read:admin"]
}

# Rule 3: dashboard can only read logs
allow if {
    input.service == "dashboard"
    input.action == "read:logs"
}

# Rule 4: admin access only allowed 0-23 hours (we can restrict this later)
# For now everyone with correct scope can access
deny_reason = "Insufficient scope" if {
    not allow
}