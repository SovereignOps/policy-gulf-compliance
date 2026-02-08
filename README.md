# SAMA Gulf Compliance Policies

This repository contains OPA (Open Policy Agent) Rego policies for compliance with SAMA (Saudi Central Bank) Cyber Security Framework.

## Structure

The policies are located in `policies/` directory. Each file corresponds to a specific SAMA control identified by its ID (e.g., `sama_3_3_9_4.rego`).

## Coverage

These policies cover controls categorized as "Tech" in the SAMA Controls Matrix.
They support multi-cloud checks for:
- AWS (`aws_*`)
- Google Cloud (`google_*`)
- Azure (`azurerm_*`)
- Oracle Cloud (`oci_*`)

## Usage with Conftest

You can use [Conftest](https://www.conftest.dev/) to run these policies against your infrastructure code (Terraform, Kubernetes, etc.).

### Prerequisites

- [Conftest](https://www.conftest.dev/install/) installed.

### Running Tests

To test your Terraform plan against these policies:

1.  Generate a Terraform plan as JSON:
    ```bash
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json
    ```

2.  Run Conftest:
    ```bash
    conftest test tfplan.json -p policies/
    ```

## Policy Customization

The generated policies are templates that verify the existence of resources related to the control. You should customize the `allow` rules in each `.rego` file to enforce specific configurations (e.g., encryption enabled, specific tags, logging enabled).

### Example: Enforcing Encryption

For `sama_3_3_9_4.rego` (Cryptographic Security), modify the AWS rule:

```rego
# AWS Rule
allow {
    input.resource_type == "aws_s3_bucket"
    input.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm == "AES256"
}
```

## Contributing

Feel free to contribute by improving the specific logic for each control.
