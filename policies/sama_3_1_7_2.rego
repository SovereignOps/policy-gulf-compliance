package sama_3_1_7_2

import data.lib.utils

# Control ID: 3.1.7.2
# Description: Education should be provided in order to equip staff  with the skills and required knowledge to securely operate the Member Organization’s information assets. 3.2 Cyber Security  Risk Management and Compliance Risk management is the ongoing process of identifying, analyzing, responding and monitoring and reviewing risks. The cyber security risk m anagement process focusses specifically on managing risks related to cyber security .  In or der to manage cyber security risks, Member Organizations should:  identify their cyber security risks – cyber security risk identification;  determine the likelihood that cyber security risks will occur and the resulting impact – cyber security risk analysis;  determine the appropriate response to cyber security risks and select relevant controls – cyber security risk response;  monitor the cyber security risk treatment and review control effectiveness  – cyber security risk monitoring and review. The compliance with the cyber security  controls should be subject to periodic review and audit.
# Requirement: Ensure compliance with 3.1.7.2 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.1.7.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.1.7.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.1.7.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.1.7.2", [input.resource_name])
}
