
import pickle
import pandas as pd

# Load the trained ML model
with open("ml_model/cloud_risk_model.pkl", "rb") as file:
    model = pickle.load(file)

def predict_risk(public_access, encryption, mfa):

    data = pd.DataFrame([{
        "public_access": public_access,
        "encryption": encryption,
        "mfa": mfa
    }])

    prediction = model.predict(data)

    return prediction[0]
