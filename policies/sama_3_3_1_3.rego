package sama_3_3_1_3

import data.lib.utils

# Control ID: 3.3.1.3
# Description: The human resource process shoul d include: a. cyber security  responsibilities and non -disclosure clauses within staff agreements (during and after the employment); b. staff  should receive cyber security  awareness at the start and during their employment; c. when disciplinary actions will be appli cable; d. screening and background check; e. post-employment cyber security  activities, such as : 1. revoking access rights; 2. returning information assets assigned (e.g. , access badge, tokens, mobile devices, all electronic and physical information).
# Requirement: Ensure compliance with 3.3.1.3 for aws_iam_user, google_project_iam_member, azurerm_role_assignment, oci_identity_user

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_iam_user"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_project_iam_member"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_role_assignment"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_identity_user"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_iam_user"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.1.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_project_iam_member"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.1.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_role_assignment"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.1.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_identity_user"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.1.3", [input.resource_name])
}
