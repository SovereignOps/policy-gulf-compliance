package sama_3_1_5_2

import data.lib.utils

# Control ID: 3.1.5.2
# Description: The Member Organization’s project management methodology should ensure that: a. cyber security  objectives are included in project objectives; b. the cyber security  function is part of all phases of the project; c. a risk assessment is performed at the start of the project to determine the cyber security  risks and to ensure that cyber security  requirements are addressed either by the existing cyber security controls (ba sed on  cyber security  standards ) or to be developed; d. cyber security  risks are registered in the project -risk register  and tracked ; e. responsibilities for cyber security  are defined and allocated; f. a cyber security review is performed by an independent internal or external party .
# Requirement: Ensure compliance with 3.1.5.2 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.1.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.1.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.1.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.1.5.2", [input.resource_name])
}
