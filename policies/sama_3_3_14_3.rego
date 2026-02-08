package sama_3_3_14_3

import data.lib.utils

# Control ID: 3.3.14.3
# Description: To support this process a security event monitoring standard should be defined, approved and implemented. a. the standard should address for all information assets the mandatory events which should be monitored , based on the classification or risk profile of the information asset.
# Requirement: Ensure compliance with 3.3.14.3 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_cloudtrail"
    input.enable_logging == true
}
allow {
    input.resource_type == "aws_flow_log"
}

# Google Cloud Rule
allow {
    input.resource_type == "google_logging_project_sink"
}

# Azure Rule
allow {
    input.resource_type == "azurerm_monitor_log_profile"
}

# OCI Rule
allow {
    input.resource_type == "oci_logging_log"
    input.is_enabled == true
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.14.3", [input.resource_name])
}
