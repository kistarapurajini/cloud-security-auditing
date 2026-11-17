
from ml_model.predict import predict_risk

risk = predict_risk(
    public_access=1,
    encryption=0,
    mfa=0
)

print("ML Predicted Risk:", risk)
