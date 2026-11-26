
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

# Load dataset
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

# Use the same test data for all models
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Define models
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

print("\n===== MACHINE LEARNING MODEL COMPARISON =====")

results = []

for name, model in models.items():

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, average="macro", zero_division=0
    )
    recall = recall_score(
        y_test, predictions, average="macro", zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, average="macro", zero_division=0
    )

    results.append({
        "Model": name,
        "Accuracy": round(accuracy * 100, 2),
        "Precision": round(precision * 100, 2),
        "Recall": round(recall * 100, 2),
        "F1 Score": round(f1 * 100, 2)
    })

# Display comparison
comparison = pd.DataFrame(results)

print(comparison.to_string(index=False))

print("\nComparison completed successfully!")
