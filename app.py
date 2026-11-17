

from flask import Flask, render_template
from scanner.misconfiguration import scan_configuration
from ml_model.predict import predict_risk
from scanner.tenant_isolation import check_tenant_isolation
import json

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():

    config_file = "dataset/sample_config.json"

    # Load cloud configuration
    with open(config_file, "r") as file:
        config = json.load(file)

    # Rule-based security scanning
    results = scan_configuration(config_file)

    # Convert configuration values into ML inputs
    public_access = int(config["public_access"])
    encryption = int(config["encryption"])
    mfa = int(config["multi_factor_authentication"])

    # ML risk prediction
    predicted_risk = predict_risk(
        public_access,
        encryption,
        mfa
    )

    # Tenant Isolation Audit
    tenant_file = "dataset/tenant_access.json"

    tenant_results = check_tenant_isolation(tenant_file)

    return render_template(
        "index.html",
        results=results,
        predicted_risk=predicted_risk,
        tenant_results=tenant_results
    )

if __name__ == "__main__":
    app.run(debug=True)
