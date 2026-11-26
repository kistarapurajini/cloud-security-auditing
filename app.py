
from flask import Flask, render_template, request
from scanner.misconfiguration import scan_configuration, scan_config_data
from ml_model.predict import predict_risk
from scanner.tenant_isolation import check_tenant_isolation

import json
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

app = Flask(__name__)

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


def get_model_comparison():

    data = pd.read_csv("dataset/cloud_training_data.csv")

    features = [
        "public_access",
        "encryption",
        "mfa",
        "unrestricted_network_access",
        "excessive_permissions",
        "logging_enabled",
        "secure_storage",
        "s3_public_access",
        "s3_protection_incomplete"
    ]

    X = data[features]
    y = data["risk"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    models = {
        "Decision Tree": DecisionTreeClassifier(random_state=42),

        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            random_state=42
        ),

        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        )
    }

    comparison_results = []

    for name, model in models.items():

        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        comparison_results.append({
            "name": name,
            "accuracy": round(
                accuracy_score(y_test, predictions) * 100, 2
            ),
            "precision": round(
                precision_score(
                    y_test, predictions,
                    average="macro",
                    zero_division=0
                ) * 100, 2
            ),
            "recall": round(
                recall_score(
                    y_test, predictions,
                    average="macro",
                    zero_division=0
                ) * 100, 2
            ),
            "f1_score": round(
                f1_score(
                    y_test, predictions,
                    average="macro",
                    zero_division=0
                ) * 100, 2
            )
        })

    best_model = max(
        comparison_results,
        key=lambda result: result["f1_score"]
    )

    return comparison_results, best_model


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():


    uploaded_file = request.files.get("config_file")

    try:

        if uploaded_file and uploaded_file.filename:

            if not uploaded_file.filename.lower().endswith(".json"):
                raise ValueError("Please upload a JSON file.")

            config = json.load(uploaded_file)

            if not isinstance(config, dict):
                raise ValueError(
                    "JSON must contain a configuration object."
                )

            for field in REQUIRED_FIELDS:

                if field not in config:
                    raise ValueError(
                        f"Missing required field: {field}"
                    )

                if not isinstance(config[field], bool):
                    raise ValueError(
                        f"{field} must be true or false."
                    )

            results = scan_config_data(config)

        else:

            config_file = "dataset/sample_config.json"

            with open(config_file, "r", encoding="utf-8") as file:
                config = json.load(file)

            if not isinstance(config, dict):
                raise ValueError(
                    "Default JSON must contain a configuration object."
                )

            for field in REQUIRED_FIELDS:

                if field not in config:
                    raise ValueError(
                        f"Missing required field: {field}"
                    )

                if not isinstance(config[field], bool):
                    raise ValueError(
                        f"{field} must be true or false."
                    )

            results = scan_configuration(config_file)

        # Extract S3 configuration
        s3_config = config.get("s3", {})

        if not isinstance(s3_config, dict):
            raise ValueError(
                "s3 must contain a configuration object."
            )

        s3_public_access = 0
        s3_protection_incomplete = 0

        if s3_config:

            public_grants = ["AllUsers", "AuthenticatedUsers"]

            acl_grants = s3_config.get("public_acl_grants", [])
            public_policy = s3_config.get(
                "public_bucket_policy", False
            )

            if not isinstance(acl_grants, list) or not all(
                isinstance(grant, str) for grant in acl_grants
            ):
                raise ValueError(
                    "public_acl_grants must be a list of strings."
                )

            if not isinstance(public_policy, bool):
                raise ValueError(
                    "public_bucket_policy must be true or false."
                )

            if (
                any(grant in public_grants for grant in acl_grants)
                or public_policy
            ):
                s3_public_access = 1

            public_access_block = s3_config.get(
                "public_access_block", {}
            )

            if not isinstance(public_access_block, dict):
                raise ValueError(
                    "public_access_block must contain an object."
                )

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

        # Existing Decision Tree prediction
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

        # Existing tenant isolation audit
        tenant_file = "dataset/tenant_access.json"
        tenant_results = check_tenant_isolation(tenant_file)



        return render_template(
            "index.html",
            results=results,
            predicted_risk=predicted_risk,
            tenant_results=tenant_results,
            model_comparison=model_comparison,
            best_model=best_model
        )

    except (
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError
    ) as error:

        return render_template(
            "index.html",
            error=str(error)
        )


if __name__ == "__main__":
    app.run(debug=True)
