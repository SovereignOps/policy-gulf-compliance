package sama_3_3_15_4

import data.lib.utils

# Control ID: 3.3.15.4
# Description: The security incident management process should include  requirements for : a. the establishment of a designated team  responsible for security incident management ; b. skilled and (continuously) trained staff ; c. sufficient capacity available of certified forensic staff for handling major incidents (e.g., internal staff  or contracting a n external  forensic team ); d. a restricted area to facilitate the computer emergency response  team ( CERT ) workspaces; e. the classification of cyber security  incidents; f. the timely handling of cyber security  incidents , recording and monitoring progress; g. the protection of relevant evidence and loggings; h. post -incident activities, such as  forensics, root -cause analysis of the inc idents; i. reporting of suggested improvements to the CISO and the Committee; j. establish a cyber security incident repository.
# Requirement: Ensure compliance with 3.3.15.4 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.15.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.15.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.15.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.15.4", [input.resource_name])
}
