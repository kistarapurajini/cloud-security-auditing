

import json

def scan_config_data(config):
    """Scan an already loaded cloud configuration."""

    findings = []

    if config.get("public_access") is True:
        findings.append("HIGH: Public access is enabled")

    if config.get("encryption") is False:
        findings.append("HIGH: Encryption is disabled")

    if config.get("multi_factor_authentication") is False:
        findings.append("MEDIUM: Multi-factor authentication is disabled")

    if not findings:
        findings.append("No configured risks detected by these checks")

    return findings


def scan_configuration(file_path):
    """Scan configuration from an existing JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    return scan_config_data(config)
