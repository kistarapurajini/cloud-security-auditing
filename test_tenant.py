
from scanner.tenant_isolation import check_tenant_isolation

results = check_tenant_isolation(
    "dataset/tenant_access.json"
)

print("\nTENANT ISOLATION AUDIT")
print("----------------------")

for result in results:
    print(result)
