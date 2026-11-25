
import pandas as pd
import pickle

from sklearn.tree import DecisionTreeClassifier

# Load training dataset
data = pd.read_csv("dataset/cloud_training_data.csv")

# Select all nine input features
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

# Input features
X = data[features]

# Target labels
y = data["risk"]

# Create and train ML model
model = DecisionTreeClassifier(random_state=42)
model.fit(X, y)

# Save trained model
with open("ml_model/cloud_risk_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("ML model trained successfully!")
print("Features used:", features)
print("Training records:", len(data))
print("Model saved successfully!")


