package sama_3_3_16_3

import data.lib.utils

# Control ID: 3.3.16.3
# Description: The threat intelligence management process should include: a. the use of internal sources, such as access control, application and infrastructure logs, IDS, IPS, security tooling, Security Information and Event Monitoring (SIEM), support functions  (e.g. , Legal, Audit, IT Helpdesk, Forensics, Fraud Management, Risk Management, Compliance); b. the use of reliable and relevant external sources, such as  SAMA, government agencies, security forums, (security) vendors, security organizations and specia list notification services; c. a defined methodology to analyze the threat information periodically ; d. the relevant details on identified or collected threats, such as  modus operandi, actors, motivation and type of threats; e. the relevance of the derived intellig ence and the action -ability for follow -up (for e.g. , SOC, Risk Management); f. sharing the relevant intelligence with the relevant stakeholders (e.g. , SAMA, BCIS  members).
# Requirement: Ensure compliance with 3.3.16.3 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.16.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.16.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.16.3", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.16.3", [input.resource_name])
}
