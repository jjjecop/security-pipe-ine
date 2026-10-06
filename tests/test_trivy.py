from scanners.dependency import run_trivy_dependency_scan
from normalizer import normalize_trivy_finding

result = run_trivy_dependency_scan(r"C:\Allprojects\Targets\NodeGoat")

all_vulns = []
for res in result["Results"]:
    vulns = res.get("Vulnerabilities", [])
    all_vulns.extend(vulns)

print("จำนวน vulnerabilities ทั้งหมด:", len(all_vulns))

first_raw = all_vulns[0]
normalized = normalize_trivy_finding(first_raw)

print("\n--- ผลลัพธ์หลัง normalize ---")
print("tool_rule_id:", normalized["tool_rule_id"])
print("title:", normalized["title"])
print("severity_native:", normalized["severity_native"])
print("cvss_score:", normalized["cvss_score"])
print("cwe_id:", normalized["cwe_id"])
print("fingerprint:", normalized["fingerprint"])
print("location:", normalized["location"])