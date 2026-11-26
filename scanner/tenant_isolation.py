
import json


def check_tenant_isolation(data):

    # Support both uploaded JSON data and existing file paths
    if isinstance(data, str):
        with open(data, "r", encoding="utf-8") as file:
            data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Tenant information must be a JSON object.")

    access_rules = data.get("access_rules")

    if not isinstance(access_rules, list):
        raise ValueError(
            "tenant_access must contain an access_rules list."
        )

    findings = []

    for index, access in enumerate(access_rules):

        if not isinstance(access, dict):
            raise ValueError(
                f"Tenant access rule {index + 1} must be an object."
            )

        source = access.get("source_tenant")
        target = access.get("target_tenant")
        allowed = access.get("allowed")

        if not isinstance(source, str) or not source.strip():
            raise ValueError(
                f"Missing or invalid source_tenant in rule {index + 1}."
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                f"Missing or invalid target_tenant in rule {index + 1}."
            )

        if not isinstance(allowed, bool):
            raise ValueError(
                f"allowed must be true or false in rule {index + 1}."
            )

        if source != target and allowed is True:
            findings.append(
                f"HIGH: Tenant {source} has cross-tenant access to {target}"
            )

    if not findings:
        findings.append(
            "No unauthorized cross-tenant access found."
        )

    return findings
