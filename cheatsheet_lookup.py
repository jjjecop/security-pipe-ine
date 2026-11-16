"""ค้นหา OWASP Cheat Sheet ที่ตรงกับ CWE (ใช้แทน find_cheatsheet_with_fallback ใน cwe_to_cheatsheet.py)

ของเดิมเทียบคำในชื่อ CWE กับชื่อไฟล์แบบเป็นส่วนของคำ ทำให้ hard ไปตรงกับ hardening
และ site ไปตรงกับ cross-site ไฟล์นี้แก้ 4 เรื่อง
1) มีตารางจับคู่ตรง (DIRECT_MAP) สำหรับ CWE ที่พบบ่อย
2) เทียบคำแบบตรงทั้งคำ
3) ไม่เลือกไฟล์ที่เหลือแต่ข้อความชี้ไปเอกสารฉบับใหม่
4) ถ้าไม่มั่นใจให้คืน None ผู้เรียกจะไปใช้ข้อมูลของ MITRE แทน
"""
import os
import re

SUFFIX = "_Cheat_Sheet.md"

DIRECT_MAP = {
    "CWE-20": "Input_Validation", "CWE-22": "Input_Validation", "CWE-176": "Input_Validation",
    "CWE-606": "Input_Validation",
    "CWE-78": "OS_Command_Injection_Defense", "CWE-88": "OS_Command_Injection_Defense",
    "CWE-79": "Cross_Site_Scripting_Prevention", "CWE-89": "SQL_Injection_Prevention",
    "CWE-943": "NoSQL_Security", "CWE-611": "XML_External_Entity_Prevention",
    "CWE-203": "Authentication", "CWE-287": "Authentication", "CWE-306": "Authentication",
    "CWE-256": "Password_Storage", "CWE-916": "Password_Storage",
    "CWE-295": "Transport_Layer_Security", "CWE-319": "Transport_Layer_Security",
    "CWE-327": "Cryptographic_Storage", "CWE-330": "Cryptographic_Storage",
    "CWE-352": "Cross-Site_Request_Forgery_Prevention",
    "CWE-384": "Session_Management", "CWE-613": "Session_Management",
    "CWE-524": "Session_Management", "CWE-525": "Session_Management", "CWE-1275": "Session_Management",
    "CWE-399": "Denial_of_Service", "CWE-400": "Denial_of_Service", "CWE-405": "Denial_of_Service",
    "CWE-407": "Denial_of_Service", "CWE-674": "Denial_of_Service", "CWE-770": "Denial_of_Service",
    "CWE-835": "Denial_of_Service", "CWE-1050": "Denial_of_Service", "CWE-1333": "Denial_of_Service",
    "CWE-434": "File_Upload", "CWE-502": "Deserialization",
    "CWE-200": "Error_Handling", "CWE-209": "Error_Handling", "CWE-248": "Error_Handling",
    "CWE-550": "Error_Handling", "CWE-497": "HTTP_Headers", "CWE-693": "HTTP_Headers",
    "CWE-117": "Logging", "CWE-532": "Logging", "CWE-778": "Logging",
    "CWE-601": "Unvalidated_Redirects_and_Forwards",
    "CWE-639": "Insecure_Direct_Object_Reference_Prevention",
    "CWE-798": "Secrets_Management", "CWE-829": "Third_Party_Javascript_Management",
    "CWE-915": "Mass_Assignment", "CWE-918": "Server_Side_Request_Forgery_Prevention",
    "CWE-1021": "Clickjacking_Defense", "CWE-1321": "Prototype_Pollution_Prevention",
    "CWE-1104": "Vulnerable_Dependency_Management", "CWE-1395": "Vulnerable_Dependency_Management",
    "CWE-1357": "Software_Supply_Chain_Security",
}

# คำกว้าง ๆ ที่อยู่ในชื่อ CWE จำนวนมาก ไม่ช่วยแยกเอกสาร
GENERIC_WORDS = {
    "improper", "incorrect", "insufficient", "insufficiently", "missing", "handling", "information",
    "exposure", "sensitive", "data", "untrusted", "site", "source", "code", "with", "without", "from",
    "through", "into", "resource", "resources", "control", "sphere", "security", "prevention", "use",
    "used", "using", "value", "values", "type", "unexpected", "dangerous", "function", "method", "critical",
}
SYNONYMS = {
    "neutralization": ["injection"], "cleartext": ["transport"], "random": ["cryptographic"],
    "credentials": ["secrets"], "consumption": ["denial"], "throttling": ["denial"],
    "complexity": ["denial"], "amplification": ["denial"],
}
# ไฟล์ที่ถูกยกเลิกจะเหลือแค่ข้อความสั้น ๆ ชี้ไปเอกสารฉบับใหม่
MIN_FILE_BYTES = 1500


def usable_files(cheatsheets_folder: str) -> list[str]:
    files = []
    for name in os.listdir(cheatsheets_folder):
        path = os.path.join(cheatsheets_folder, name)
        if name.endswith(".md") and os.path.getsize(path) >= MIN_FILE_BYTES:
            files.append(name)
    return sorted(files)


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _best_by_name(keywords: set[str], files: list[str], min_score: int) -> str | None:
    best, best_score = None, 0
    for name in files:
        score = len(keywords & _words(name.replace(SUFFIX, "")))
        if score > best_score:
            best, best_score = name, score
    return best if best_score >= min_score else None


def find_cheatsheet(cwe_id: str, cwe_description: str, owasp_category: str | None,
                    index_data: dict, cheatsheets_folder: str) -> str | None:
    usable = usable_files(cheatsheets_folder)

    direct = DIRECT_MAP.get(cwe_id)
    if direct and direct + SUFFIX in usable:
        return direct + SUFFIX

    keywords = {w for w in _words(cwe_description) if len(w) > 3 and w not in GENERIC_WORDS}
    for word in list(keywords):
        keywords.update(SYNONYMS.get(word, []))

    code = re.match(r"(A\d{1,2}:\d{4})", owasp_category or "")
    category_files = [f for f in index_data.get(code.group(1) if code else owasp_category, []) if f in usable]
    hit = _best_by_name(keywords, category_files, min_score=1)
    if hit:
        return hit
    # นอกหมวดต้องตรงอย่างน้อย 2 คำ ไม่อย่างนั้นถือว่าไม่มีเอกสาร
    return _best_by_name(keywords, usable, min_score=2)
