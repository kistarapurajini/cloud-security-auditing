
import itertools
import pandas as pd

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

records = []

# Generate all 512 combinations of nine binary features
for values in itertools.product([0, 1], repeat=9):
    config = dict(zip(features, values))

    # Calculate risk using a documented rule
    if (
        config["public_access"] == 1
        or config["s3_public_access"] == 1
        or (
            config["unrestricted_network_access"] == 1
            and config["excessive_permissions"] == 1
        )
    ):
        risk = "High"

    else:
        moderate_score = (
            (1 - config["encryption"]) * 2
            + (1 - config["mfa"])
            + (1 - config["logging_enabled"])
            + (1 - config["secure_storage"]) * 2
            + config["s3_protection_incomplete"] * 2
            + config["unrestricted_network_access"]
            + config["excessive_permissions"]
        )

        if moderate_score >= 3:
            risk = "Medium"
        else:
            risk = "Low"

    records.append({**config, "risk": risk})

# Save dataset
df = pd.DataFrame(records)
df.to_csv("dataset/cloud_training_data.csv", index=False)

print("New dataset generated successfully!")
print("Total records:", len(df))

print("\nRisk category distribution:")
print(df["risk"].value_counts())

print("\nDataset saved successfully!")
