package sama_3_3_9_4

import data.lib.utils

# Control ID: 3.3.9.4
# Description: The cryptographic security standard should include: a. an overview of the approved cryptographic solutions  and relevant rest rictions (e.g., technically, legally) ; b. the circumstances when the approved cryptographic solutions should be applied; c. the management of encryption keys , including lifecycle management, archiving and recovery.
# Requirement: Ensure compliance with 3.3.9.4 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_s3_bucket"
    input.server_side_encryption_configuration
}
allow {
    input.resource_type == "aws_db_instance"
    input.storage_encrypted == true
}
allow {
    input.resource_type == "aws_ebs_volume"
    input.encrypted == true
}

# Google Cloud Rule
allow {
    input.resource_type == "google_storage_bucket"
    input.encryption
}
allow {
    input.resource_type == "google_compute_disk"
    input.disk_encryption_key
}

# Azure Rule
allow {
    input.resource_type == "azurerm_storage_account"
    input.enable_https_traffic_only == true
}
allow {
    input.resource_type == "azurerm_managed_disk"
    input.encryption_settings
}

# OCI Rule
allow {
    input.resource_type == "oci_objectstorage_bucket"
    input.kms_key_id
}
allow {
    input.resource_type == "oci_core_volume"
    input.kms_key_id
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.9.4", [input.resource_name])
}
