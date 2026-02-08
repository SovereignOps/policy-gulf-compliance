package sama_3_3_8_5

import data.lib.utils

# Control ID: 3.3.8.5
# Description: The infrastructure security standards should cover all instances of infrastructure  (e.g., operating systems, servers, virtual machine s, firewalls, network  devices , IDS, IPS, wireless  network, gateway servers, proxy servers, email gateways, external connections,  databases, file -shares, workstations, laptops, tablets, mobile devices , PBX ).
# Requirement: Ensure compliance with 3.3.8.5 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_security_group"
}
allow {
    input.resource_type == "aws_network_acl"
}

# Google Cloud Rule
allow {
    input.resource_type == "google_compute_firewall"
}

# Azure Rule
allow {
    input.resource_type == "azurerm_network_security_group"
}

# OCI Rule
allow {
    input.resource_type == "oci_core_security_list"
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.8.5", [input.resource_name])
}
