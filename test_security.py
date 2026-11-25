
from scanner.misconfiguration import scan_s3_public_access
from ml_model.predict import predict_risk
from scanner.tenant_isolation import check_tenant_isolation


def test_s3_secure_configuration():
    config = {
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True
        },
        "public_acl_grants": [],
        "public_bucket_policy": False
    }

    results = scan_s3_public_access(config)

    assert any("checks passed" in result for result in results)


def test_s3_public_access():
    config = {
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False
        },
        "public_acl_grants": ["AllUsers"],
        "public_bucket_policy": True
    }

    results = scan_s3_public_access(config)

    assert any("CRITICAL" in result for result in results)


def test_ml_prediction():
    risk = predict_risk(
        0, 1, 1, 0, 0, 1, 1, 1, 1
    )

    assert risk in ["Low", "Medium", "High"]


def test_tenant_isolation():
    results = check_tenant_isolation("dataset/tenant_access.json")

    assert isinstance(results, list)
