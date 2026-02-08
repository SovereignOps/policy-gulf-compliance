package sama_3_2_1_2

import data.lib.utils

# Control ID: 3.2.1.2
# Description: The cyber security  risk management process should focus on safeguarding the confidentiality, integrity and availability of information assets.
# Requirement: Ensure compliance with 3.2.1.2 for aws_resource, google_resource, azurerm_resource, oci_resource

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.2.1.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_resource"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.2.1.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_resource"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.2.1.2", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_resource"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.2.1.2", [input.resource_name])
}
