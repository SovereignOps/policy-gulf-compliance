package sama_3_3_13_8

import data.lib.utils

# Control ID: 3.3.13.8
# Description: high availability of the electronic banking services  should be ensured;
# Requirement: Ensure compliance with 3.3.13.8 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_lb"
}
allow {
    input.resource_type == "aws_autoscaling_group"
}
allow {
    input.resource_type == "aws_db_instance"
    input.multi_az == true
}

# Google Cloud Rule
allow {
    input.resource_type == "google_compute_region_instance_group_manager"
}

# Azure Rule
allow {
    input.resource_type == "azurerm_lb"
}

# OCI Rule
allow {
    input.resource_type == "oci_load_balancer"
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.13.8", [input.resource_name])
}
