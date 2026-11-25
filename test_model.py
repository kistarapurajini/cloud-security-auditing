
from ml_model.predict import predict_risk

# Test configuration with S3 public access risks
risk = predict_risk(
    public_access=0,
    encryption=1,
    mfa=1,
    unrestricted_network_access=0,
    excessive_permissions=0,
    logging_enabled=1,
    secure_storage=1,
    s3_public_access=1,
    s3_protection_incomplete=1
)

print("ML Predicted Risk:", risk)


