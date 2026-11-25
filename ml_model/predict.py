
import pickle
import pandas as pd

# Load the trained ML model
with open("ml_model/cloud_risk_model.pkl", "rb") as file:
    model = pickle.load(file)


def predict_risk(
    public_access,
    encryption,
    mfa,
    unrestricted_network_access,
    excessive_permissions,
    logging_enabled,
    secure_storage,
    s3_public_access,
    s3_protection_incomplete
):

    data = pd.DataFrame([{
        "public_access": public_access,
        "encryption": encryption,
        "mfa": mfa,
        "unrestricted_network_access": unrestricted_network_access,
        "excessive_permissions": excessive_permissions,
        "logging_enabled": logging_enabled,
        "secure_storage": secure_storage,
        "s3_public_access": s3_public_access,
        "s3_protection_incomplete": s3_protection_incomplete
    }])

    prediction = model.predict(data)

    return prediction[0]


