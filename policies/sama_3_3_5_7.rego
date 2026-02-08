package sama_3_3_5_7

import data.lib.utils

# Control ID: 3.3.5.7
# Description: an audit trail of submitted, approved and processed user access requests and revocation requ ests should be established; c. user access management should be supported by automation; d. centralization of the identity and access management function; e. multi -factor authentication for sensitive and critical systems and profiles; f. privilege d and remote access management , which should address: 1. the allocation and restricted use of privileged and remote access , specifying : a. multi-factor authentication shoul d be used for all remote access; b. multi-factor authentication should be used for privilege access on critical s ystems based on a risk assessment ; 2. the periodic review of users with privileged and remote accounts ; 3. individual accountability ; 4. the use of non -personal privileged accounts , including: a. limitation and monitoring; b. confidentiality of passwords; c. changing passwords frequently and at the end of each session .
# Requirement: Ensure compliance with 3.3.5.7 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_cloudtrail"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_logging_project_sink"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_monitor_log_profile"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_logging_log"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_cloudtrail"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.5.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.5.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.5.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.5.7", [input.resource_name])
}
