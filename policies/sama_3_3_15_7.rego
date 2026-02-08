package sama_3_3_15_7

import data.lib.utils

# Control ID: 3.3.15.7
# Description: The Member Organization should submit a formal incident report  ‘SAMA IT Risk Supervision’  after resuming operations , including  the following incident details : a. title of incident; b. classification of the incident (medium or high); c. date and time of incident  occurred ; d. date and time of incident detected; e. information assets involved; f. (technical) detai ls of the incident; g. root -cause analysis; h. corrective activities performed and planned; i. description of impact  (e.g., loss of data, disruption of services, unauthorized modification of data , (un)intended data leakage, number of customers impacted ); j. total est imated cost of incident; k. estimated cost of corrective actions.
# Requirement: Ensure compliance with 3.3.15.7 for aws_resource, google_resource, azurerm_resource, oci_resource

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_resource"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_resource"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_resource"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_resource"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_resource"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.15.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_resource"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.15.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_resource"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.15.7", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_resource"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.15.7", [input.resource_name])
}
