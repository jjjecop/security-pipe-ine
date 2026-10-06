import os

CHEATSHEETS_FOLDER = "CheatSheetSeries/cheatsheets"

# คำค้นเฉพาะสำหรับแต่ละ CWE ที่ยังไม่เจอ (ไม่ใช่แค่คำจาก description)
CONTENT_SEARCH_TERMS = {
    "CWE-22":   ["path traversal", "directory traversal", "../"],
    "CWE-203":  ["timing attack", "side channel", "constant time"],
    "CWE-248":  ["uncaught exception", "unhandled exception"],
    "CWE-415":  ["double free", "use-after-free", "memory safety"],
    "CWE-416":  ["use after free", "use-after-free", "dangling pointer"],
    "CWE-436":  ["parser differential", "interpretation", "smuggling"],
    "CWE-524":  ["cache-control", "no-store", "caching sensitive"],
    "CWE-749":  ["dangerous method", "exposed method", "debug endpoint"],
    "CWE-787":  ["buffer overflow", "out-of-bounds", "bounds checking"],
    "CWE-1357": ["supply chain", "third-party trust", "dependency confusion"],
}

all_files = os.listdir(CHEATSHEETS_FOLDER)

for cwe_id, terms in CONTENT_SEARCH_TERMS.items():
    found_in = []
    for filename in all_files:
        filepath = os.path.join(CHEATSHEETS_FOLDER, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().lower()
        except Exception:
            continue
        if any(term in content for term in terms):
            found_in.append(filename)

    if found_in:
        print(f"{cwe_id}: ✅ เจอในเนื้อหาไฟล์ -> {found_in}")
    else:
        print(f"{cwe_id}: ❌ ไม่เจอแม้แต่ในเนื้อหา (ยืนยันว่าต้องเขียนมือจริง)")