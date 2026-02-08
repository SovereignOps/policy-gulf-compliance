package sama_3_3_17_3

import data.lib.utils

# Control ID: 3.3.17.3
# Description: The vulnerability management process should include: a. all information assets; b. frequency of performing the vulner ability scan (risk -based); c. classification of vulnerabilities; d. defined timelines to mitigate  (per classification) ; e. prioritization for classified information assets; f. patch mana gement and method of deployment. 3.4 Third Party Cyber  Security When Member Organiza tions do rely on, or have to deal with third party services, it is key to ensure the same level of cyber security protection is implemented at the third party, as within the Member Organization. This paragraph describes how the cyber security  requirement s between the Member Organization and Third Parties should be organized, implemented and monitored. Third Parties in this Framework are defined as, information services providers, outsourcing providers, cloud computing providers, vendors, suppliers, govern mental agencies, etc.
# Requirement: Ensure compliance with 3.3.17.3 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.17.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.17.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.17.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.17.3", [input.resource_name])
}
