

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
    "multi_factor_authentication"
]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    uploaded_file = request.files.get("config_file")
    print("Uploaded file:", uploaded_file)
    print("Filename:", uploaded_file.filename if uploaded_file else "No file") 

    try:
        if uploaded_file and uploaded_file.filename:

            # Check file extension
            if not uploaded_file.filename.lower().endswith(".json"):
                raise ValueError("Please upload a JSON file.")

            # Read uploaded JSON without saving it
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

            results = scan_configuration(config_file)

        # ML risk prediction
        predicted_risk = predict_risk(
            int(config["public_access"]),
            int(config["encryption"]),
            int(config["multi_factor_authentication"])
        )

        # Tenant isolation audit remains unchanged
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
