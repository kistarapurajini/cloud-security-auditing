
import json


def scan_s3_public_access(s3_config):
    """Check S3 public access using normalized AWS configuration data."""

    findings = []

    public_access_block = s3_config.get("public_access_block", {})

    required_protections = [
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets"
    ]

    # Check all four S3 public access protections
    incomplete_protections = []

    for setting in required_protections:
        value = public_access_block.get(setting)

        if not isinstance(value, bool):
            incomplete_protections.append(setting)
        elif value is False:
            incomplete_protections.append(setting)

    if incomplete_protections:
        findings.append(
            "MEDIUM: S3 Public Access Block protections are incomplete: "
            + ", ".join(incomplete_protections)
        )

    # Check public ACL grants
    public_grants = ["AllUsers", "AuthenticatedUsers"]

    acl_grants = s3_config.get("public_acl_grants", [])

    if not isinstance(acl_grants, list):
        raise ValueError("public_acl_grants must be a list.")

    public_acl_found = any(
        grant in public_grants for grant in acl_grants
    )

    # Check public bucket policy
    public_policy = s3_config.get("public_bucket_policy", False)

    if not isinstance(public_policy, bool):
        raise ValueError("public_bucket_policy must be true or false.")

    if public_acl_found or public_policy:
        findings.append(
            "CRITICAL: S3 bucket has public access through ACL or bucket policy"
        )
    elif not incomplete_protections:
        findings.append(
            "S3 public access checks passed for the supplied configuration"
        )

    return findings


def scan_config_data(config):
    """Scan cloud configuration for security misconfigurations."""

    findings = []

    # AWS S3 public access check
    if "s3" in config:
        if not isinstance(config["s3"], dict):
            raise ValueError("s3 must contain a configuration object.")

        findings.extend(scan_s3_public_access(config["s3"]))

    else:
        # Existing simplified public access check
        if config.get("public_access") is True:
            findings.append("HIGH: Public access is enabled")

    # Existing encryption check
    if config.get("encryption") is False:
        findings.append("HIGH: Encryption is disabled")

    # MFA check
    if config.get("multi_factor_authentication") is False:
        findings.append(
            "MEDIUM: Multi-factor authentication is disabled"
        )

    # Network security check
    if config.get("unrestricted_network_access") is True:
        findings.append(
            "HIGH: Unrestricted network access is enabled"
        )

    # Permission check
    if config.get("excessive_permissions") is True:
        findings.append(
            "HIGH: Excessive user permissions detected"
        )

    # Logging check
    if config.get("logging_enabled") is False:
        findings.append("MEDIUM: Security logging is disabled")

    # Storage security check
    if config.get("secure_storage") is False:
        findings.append(
            "HIGH: Secure storage configuration is disabled"
        )

    if not findings:
        findings.append(
            "No configured risks detected by these checks"
        )

    return findings


def scan_configuration(file_path):
    """Scan configuration from an existing JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    return scan_config_data(config)


