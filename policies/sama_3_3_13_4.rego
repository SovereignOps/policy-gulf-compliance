package sama_3_3_13_4

import data.lib.utils

# Control ID: 3.3.13.4
# Description: Electronic banking services security standard should cover: a. use of brand protection measures to protect online services including social media. b. online , mobile  and phone  banking: 1. use of official application stores and websites  (applicable for online and mobile banking) ; 2. use of detection measures and take -down of malicious apps  and websites  (applicable for online and mobile banking) ; 3. use of sandboxing (applicable for online and mobi le banking) ;
# Requirement: Ensure compliance with 3.3.13.4 for aws_resource, google_resource, azurerm_resource, oci_resource

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.13.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_resource"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.13.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_resource"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.13.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_resource"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.13.4", [input.resource_name])
}
