from scanners.sast import run_semgrep_scan
from normalizer import normalize_semgrep_finding

result = run_semgrep_scan(r"C:\Allprojects\Targets\NodeGoat")

print("จำนวน findings:", len(result["results"]))

first_raw = result["results"][0]
normalized = normalize_semgrep_finding(first_raw)

print("\n--- ผลลัพธ์หลัง normalize ---")
print("tool_rule_id", normalized["tool_rule_id"])
print("title:", normalized["title"])
print("cwe_id:", normalized["cwe_id"])
print("owasp_category:", normalized["owasp_category"])
print("fingerprint:", normalized["fingerprint"])
print("location:", normalized["location"])