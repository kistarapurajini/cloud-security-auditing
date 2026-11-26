
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Load dataset
data = pd.read_csv("dataset/cloud_training_data.csv")

# Input features
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

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Train evaluation model
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

# Predict test data
y_pred = model.predict(X_test)

# Calculate evaluation metrics
print("\n===== ML MODEL EVALUATION =====")

print("Accuracy:", accuracy_score(y_test, y_pred))

print(
    "Precision:",
    precision_score(y_test, y_pred, average="macro", zero_division=0)
)

print(
    "Recall:",
    recall_score(y_test, y_pred, average="macro", zero_division=0)
)

print(
    "F1 Score:",
    f1_score(y_test, y_pred, average="macro", zero_division=0)
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred, labels=["High", "Low", "Medium"]))

print("\nClassification Report:")
print(classification_report(y_test, y_pred, zero_division=0))
