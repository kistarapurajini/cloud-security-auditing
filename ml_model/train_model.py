
import pandas as pd
import pickle

from sklearn.tree import DecisionTreeClassifier

# Load training dataset
data = pd.read_csv("dataset/cloud_training_data.csv")

# Select input features
X = data[["public_access", "encryption", "mfa"]]

# Select target labels
y = data["risk"]

# Create and train ML model
model = DecisionTreeClassifier(random_state=42)
model.fit(X, y)

# Save trained model
with open("ml_model/cloud_risk_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("ML model trained successfully!")
print("Model saved successfully!")
