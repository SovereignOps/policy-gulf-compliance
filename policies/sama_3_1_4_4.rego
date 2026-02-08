package sama_3_1_4_4

import data.lib.utils

# Control ID: 3.1.4.4
# Description: cyber security  programs (e.g., awareness program, data classification program, data privacy, data leakage prevention, key cyber security  improvements);
# Requirement: Ensure compliance with 3.1.4.4 for aws_resource, google_resource, azurerm_resource, oci_resource

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.1.4.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_resource"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.1.4.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_resource"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.1.4.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_resource"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.1.4.4", [input.resource_name])
}
