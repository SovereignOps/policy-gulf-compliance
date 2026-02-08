package sama_3_2_5_2

import data.lib.utils

# Control ID: 3.2.5.2
# Description: Cyber security  audits should be performe d according to the Member Organization’s audit manual and audit plan. 3.3 Cyber  Security Operations and Technology In order to safeguard the protection of the operations and technology of the Member Organization's information assets and its staff , third parties and customers, the Member Organizations have to ensure that security requirements for their information assets and the supporting processes are defined, approved and implemented. The compliance with these cyber security  requirements should be monitored and the effectiveness of the cyber security  controls should be periodically  measured and evaluated in order to identify potential revisions of the controls or measurements.
# Requirement: Ensure compliance with 3.2.5.2 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.2.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.2.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.2.5.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.2.5.2", [input.resource_name])
}
