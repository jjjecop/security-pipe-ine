from scanners.container import run_trivy_container_scan
from normalizer import normalize_trivy_container_finding

result = run_trivy_container_scan("nodegoat:latest")

all_vulns = []

for res in result["Results"]:
    vulns = res.get("Vulnerabilities", [])
    all_vulns.extend(vulns)

print("จำนวน vulnerabilities ทั้งหมด:", len(all_vulns))

first_raw = all_vulns[0]
normalized = normalize_trivy_container_finding(first_raw, "nodegoat:latest")

print("\n-- ผลลัพธ์หลัง normalize --")
print("tool:", normalized["tool"])
print("tool_rule_id:", normalized["tool_rule_id"])
print("title:", normalized["title"])
print("severity_native:", normalized["severity_native"])
print("cvss_score:", normalized["cvss_score"])
print("location_type:", normalized["location_type"])
print("location:", normalized["location"])
print("fingerprint:", normalized["fingerprint"])