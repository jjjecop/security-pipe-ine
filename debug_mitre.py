import csv, re

csv.field_size_limit(10_000_000)

pattern = re.compile(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000")

total = 0
matched = 0
with open("mitre/1000.csv", encoding="utf-8-sig", newline="") as f:
    for row in csv.DictReader(f):
        rel = row.get("Related Weaknesses") or ""
        total += 1 
        if pattern.search(rel):
            matched += 1
        if total <= 3:
            print(f"ตัวอย่าง CWE-{row['CWE-ID']}: {rel[:200]!r}")
        if row.get("CWE-ID") == "436":
            print(f"\nข้อมูลดิบของ CWE-436: {rel!r}")
        elif ":436:" in rel:
            print(f"CWE-{row['CWE-ID']} อ้างอิง 436: {rel[:200]!r}")

print(f"\nแถวที่ regex จับได้: {matched} จาก {total}")