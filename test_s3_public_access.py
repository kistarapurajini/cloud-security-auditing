
from scanner.misconfiguration import scan_s3_public_access

# Test 1: Fully secure S3 configuration
secure_config = {
    "public_access_block": {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True
    },
    "public_acl_grants": [],
    "public_bucket_policy": False
}

# Test 2: Public ACL access
public_acl_config = {
    "public_access_block": {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True
    },
    "public_acl_grants": ["AllUsers"],
    "public_bucket_policy": False
}

# Test 3: Public bucket policy
public_policy_config = {
    "public_access_block": {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True
    },
    "public_acl_grants": [],
    "public_bucket_policy": True
}

# Test 4: Incomplete public access protections
incomplete_config = {
    "public_access_block": {
        "block_public_acls": False,
        "ignore_public_acls": False,
        "block_public_policy": True,
        "restrict_public_buckets": True
    },
    "public_acl_grants": [],
    "public_bucket_policy": False
}

# Test 5: Missing protection settings
missing_config = {
    "public_access_block": {
        "block_public_acls": True,
        "ignore_public_acls": True
    },
    "public_acl_grants": [],
    "public_bucket_policy": False
}

test_cases = [
    ("Secure S3 Configuration", secure_config),
    ("Public ACL Access", public_acl_config),
    ("Public Bucket Policy", public_policy_config),
    ("Incomplete Protections", incomplete_config),
    ("Missing Protection Settings", missing_config)
]

for name, config in test_cases:
    print("\n================================")
    print("TEST:", name)
    print("================================")

    results = scan_s3_public_access(config)

    if results:
        for result in results:
            print(result)
    else:
        print("No findings")

