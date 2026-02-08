package sama_3_3_8_4

import data.lib.utils

# Control ID: 3.3.8.4
# Description: The infrastructure security standards should cover all instances of infrastructure available  in the main datacenter(s) , the disaster recovery data site(s)  and office spaces.
# Requirement: Ensure compliance with 3.3.8.4 for aws_db_instance, google_sql_database_instance, azurerm_sql_server, oci_database_db_system

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_db_instance"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_sql_database_instance"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_sql_server"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_database_db_system"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_db_instance"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.8.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_sql_database_instance"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.8.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_sql_server"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.8.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_database_db_system"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.8.4", [input.resource_name])
}
