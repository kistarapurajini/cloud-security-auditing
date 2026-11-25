
from flask import Flask, render_template, request
from scanner.misconfiguration import scan_configuration, scan_config_data
from ml_model.predict import predict_risk
from scanner.tenant_isolation import check_tenant_isolation
import json

app = Flask(__name__)

# Limit uploaded files to 1 MB
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

REQUIRED_FIELDS = [
    "public_access",
    "encryption",
    "multi_factor_authentication",
    "unrestricted_network_access",
    "excessive_permissions",
    "logging_enabled",
    "secure_storage"
]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    uploaded_file = request.files.get("config_file")

    try:
        if uploaded_file and uploaded_file.filename:

            # Check file extension
            if not uploaded_file.filename.lower().endswith(".json"):
                raise ValueError("Please upload a JSON file.")

            # Read uploaded JSON
            config = json.load(uploaded_file)

            if not isinstance(config, dict):
                raise ValueError("JSON must contain a configuration object.")

            # Validate required fields
            for field in REQUIRED_FIELDS:
                if field not in config:
                    raise ValueError(f"Missing required field: {field}")

                if not isinstance(config[field], bool):
                    raise ValueError(f"{field} must be true or false.")

            # Scan uploaded configuration
            results = scan_config_data(config)

        else:
            # Use existing sample configuration
            config_file = "dataset/sample_config.json"

            with open(config_file, "r", encoding="utf-8") as file:
                config = json.load(file)

            if not isinstance(config, dict):
                raise ValueError("Default JSON must contain a configuration object.")

            # Validate default configuration
            for field in REQUIRED_FIELDS:
                if field not in config:
                    raise ValueError(f"Missing required field: {field}")

                if not isinstance(config[field], bool):
                    raise ValueError(f"{field} must be true or false.")

            results = scan_configuration(config_file)

        # Extract AWS S3 configuration
        s3_config = config.get("s3", {})

        if not isinstance(s3_config, dict):
            raise ValueError("s3 must contain a configuration object.")

        s3_public_access = 0
        s3_protection_incomplete = 0

        if s3_config:

            public_grants = ["AllUsers", "AuthenticatedUsers"]

            acl_grants = s3_config.get("public_acl_grants", [])
            public_policy = s3_config.get("public_bucket_policy", False)

            if not isinstance(acl_grants, list) or not all(
                isinstance(grant, str) for grant in acl_grants
            ):
                raise ValueError("public_acl_grants must be a list of strings.")

            if not isinstance(public_policy, bool):
                raise ValueError("public_bucket_policy must be true or false.")

            if any(grant in public_grants for grant in acl_grants) or public_policy:
                s3_public_access = 1

            public_access_block = s3_config.get("public_access_block", {})

            if not isinstance(public_access_block, dict):
                raise ValueError("public_access_block must contain an object.")

            required_protections = [
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets"
            ]

            if any(
                public_access_block.get(setting) is not True
                for setting in required_protections
            ):
                s3_protection_incomplete = 1

        # ML risk prediction using all nine features
        predicted_risk = predict_risk(
            int(config["public_access"]),
            int(config["encryption"]),
            int(config["multi_factor_authentication"]),
            int(config["unrestricted_network_access"]),
            int(config["excessive_permissions"]),
            int(config["logging_enabled"]),
            int(config["secure_storage"]),
            s3_public_access,
            s3_protection_incomplete
        )

        # Tenant isolation audit
        tenant_file = "dataset/tenant_access.json"
        tenant_results = check_tenant_isolation(tenant_file)

        return render_template(
            "index.html",
            results=results,
            predicted_risk=predicted_risk,
            tenant_results=tenant_results
        )

    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        return render_template(
            "index.html",
            error=str(error)
        )


if __name__ == "__main__":
    app.run(debug=True)


