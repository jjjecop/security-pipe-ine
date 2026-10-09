import hashlib
import os
import re
from urllib.parse import urlsplit, urlunsplit

def make_fingerprint(tool_rule_id: str, file_path: str, code_key: str) -> str:
    raw_string = f"{tool_rule_id}:{file_path}:{code_key}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

def semgrep_code_key(raw: dict) -> str:
    # ใช้โค้ดที่ match เป็น key เพื่อให้ fingerprint ไม่เปลี่ยนเมื่อบรรทัดเลื่อน
    # semgrep เวอร์ชันที่ไม่ได้ login จะคืน "requires login" แทนโค้ด จึง fallback เป็นเลขบรรทัด
    lines = (raw["extra"].get("lines") or "").strip()
    if lines and lines != "requires login":
        return " ".join(lines.split())
    return f"line:{raw['start']['line']}"

def as_list(value) -> list:
    # Semgrep metadata: some rules use a list, some use a single string
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def normalize_semgrep_finding(raw: dict, base_path: str | None = None) -> dict:
    tool_rule_id = raw["check_id"]
    file_path = raw["path"]
    if base_path:
        file_path = os.path.relpath(file_path, base_path).replace("\\", "/")

    metadata = raw["extra"].get("metadata", {})
    cwe_list = as_list(metadata.get("cwe"))
    owasp_list = as_list(metadata.get("owasp"))

    return {
        "tool": "semgrep",
        "tool_rule_id": tool_rule_id,
        "title": raw["extra"]["message"][:200],
        "description": raw["extra"]["message"],
        "severity_native": raw["extra"].get("severity"),
        "cwe_id": cwe_list[0].split(":")[0] if cwe_list else None,
        "owasp_category": owasp_list[0] if owasp_list else None,
        "confidence": metadata.get("confidence"),
        "location_type": "code",
        "location": {
            "type": "code",
            "code": {
                "file_path": file_path,
                "line_start": raw["start"]["line"],
                "line_end": raw["end"]["line"]
            },
        },
        "fingerprint": make_fingerprint(tool_rule_id, file_path, semgrep_code_key(raw)),
    }


def make_dependency_fingerprint(package_name: str, cve_id: str, installed_version: str | None = None) -> str:
    # ใส่เวอร์ชันด้วย เพราะ npm อาจติดตั้ง package เดียวกันหลายเวอร์ชันพร้อมกัน
    raw_string = f"{package_name}@{installed_version or ''}:{cve_id}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()


def normalize_trivy_finding(raw: dict) -> dict:
    package_name = raw["PkgName"]
    cve_id = raw["VulnerabilityID"]

    cwe_list = raw.get("CweIDs", [])

    cvss_data = raw.get("CVSS", {})
    cvss_score = None
    for source in ["nvd", "ghsa", "redhat"]:
        if source in cvss_data and "V3Score" in cvss_data[source]:
            cvss_score = cvss_data[source]["V3Score"]
            break

    return {
        "tool": "trivy-dep",
        "tool_rule_id": cve_id,
        "title": raw.get("Title", cve_id)[:200],
        "description": raw.get("Description"),
        "severity_native": raw.get("Severity"),
        "cvss_score": cvss_score,
        "cwe_id": cwe_list[0] if cwe_list else None,
        "owasp_category": None,
        "confidence": None,
        "location_type": "dependency",
        "location": {
            "type": "dependency",
            "dependency": {
                "package_name": package_name,
                "installed_version": raw.get("InstalledVersion"),
                "fixed_version": raw.get("FixedVersion"),
                "cve_id": cve_id,
            },
        },
        "fingerprint": make_dependency_fingerprint(package_name, cve_id, raw.get("InstalledVersion")),
    }

def normalize_trivy_container_finding(raw: dict, image_ref: str) -> dict:
    package_name = raw["PkgName"]
    cve_id = raw["VulnerabilityID"]

    cwe_list = raw.get("CweIDs", [])

    cvss_data = raw.get("CVSS", {})
    cvss_score = None 
    for source in ["nvd", "ghsa", "redhat"]:
        if source in cvss_data and "V3Score" in cvss_data[source]:
            cvss_score = cvss_data[source]["V3Score"]
            break

    return {
        "tool": "trivy-container",
        "tool_rule_id": cve_id,
        "title": raw.get("Title", cve_id)[:200],
        "description": raw.get("Description"),
        "severity_native": raw.get("Severity"),
        "cvss_score": cvss_score,
        "cwe_id": cwe_list[0] if cwe_list else None,
        "owasp_category": None,
        "confidence": None,
        "location_type": "container_image",
        "location": {
            "type": "container_image",
            "container_image": {
                "image_ref": image_ref,
                "os_package": package_name,
                "installed_version": raw.get("InstalledVersion"),
                "fixed_version": raw.get("FixedVersion"),
                "cve_id": cve_id
            },
        },
        "fingerprint": make_dependency_fingerprint(f"{image_ref}:{package_name}", cve_id, raw.get("InstalledVersion")),
    }


ZAP_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}

ZAP_CONFIDENCE_MAP = {
    "1": "low",
    "2": "medium",
    "3": "high",
}

def make_dast_fingerprint(plugin_id: str, url: str, method: str | None, param: str | None) -> str:
    # ตัด query string / fragment ออก เพื่อไม่ให้ URL เดียวกันที่ค่า parameter ต่างกันกลายเป็นหลาย finding
    parts = urlsplit(url)
    base_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    raw_string = f"{plugin_id}:{method or ''}:{base_url}:{param or ''}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

def normalize_zap_finding(alert: dict, instance: dict) -> dict:
    plugin_id = alert["pluginid"]
    url = instance["uri"]

    risk_code = alert.get("riskcode", "0")
    confidence_code = alert.get("confidence", "1")

    description_raw = alert.get("desc", "")
    description_clean = re.sub("<[^<]+?>", "", description_raw)

    return {
        "tool": "zap",
        "tool_rule_id": plugin_id,
        "title": alert.get("name",plugin_id)[:200],
        "description": description_clean,
        "severity_native": ZAP_RISK_MAP.get(risk_code, "info"),
        "cvss_score": None,
        "cwe_id": alert.get("cweid"),
        "owasp_category": None,
        "confidence": ZAP_CONFIDENCE_MAP.get(confidence_code, "low"),
        "location_type": "http_endpoint",
        "location": {
            "type": "http_endpoint",
            "http_endpoint": {
                "url": url,
                "method": instance.get("method"),
                "parameter": instance.get("param"),
                "attack_evidence": instance.get("evidence"),
            },
        },
        "fingerprint": make_dast_fingerprint(plugin_id, url, instance.get("method"), instance.get("param")),
    }