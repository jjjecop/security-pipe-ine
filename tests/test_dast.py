from scanners.dast import run_zap_baseline_scan
from normalizer import normalize_zap_finding

result = run_zap_baseline_scan(
    target_url="http://host.docker.internal:4000",
    work_dir=r"C:\Allprojects\Targets\NodeGoat",
)

alerts = result["site"][0]["alerts"]

print("จำนวน alerts ทั้งหมด", len(alerts))

all_normalized = []
for alert in alerts:
    for instance in alert["instances"]: 
        normalized = normalize_zap_finding(alert, instance)
        all_normalized.append(normalized)

print("จำนวน findings ทั้งหมด (หลังแตก instances):", len(all_normalized))

first = all_normalized[0]
print("\n--- ผลลัพธ์ finding แรก ---")
print("tool_rule_id:", first["tool_rule_id"])
print("title:", first["title"])
print("severity_native:", first["severity_native"])
print("confidence:", first["confidence"])
print("location:", first["location"])
print("fingerprint:", first["fingerprint"])