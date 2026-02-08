package sama_3_3_11_4

import data.lib.utils

# Control ID: 3.3.11.4
# Description: Information assets should be disposed in accordance with legal and regulatory requirements, when no longer requ ired (i.e. meeting data privacy regulations to avoid unauthorized access and avoid (un)intended data leakage) .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
