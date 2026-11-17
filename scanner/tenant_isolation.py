
import json

def check_tenant_isolation(file_path):

    with open(file_path, "r") as file:
        data = json.load(file)

    findings = []

    for access in data["access_rules"]:

        source = access["source_tenant"]
        target = access["target_tenant"]
        allowed = access["allowed"]

        if source != target and allowed is True:
            findings.append(
                f"HIGH: Tenant {source} has cross-tenant access to {target}"
            )

    if not findings:
        findings.append("No unauthorized cross-tenant access found in the sample rules")

    return findings
