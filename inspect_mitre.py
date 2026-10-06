from sqlalchemy.orm import Session
from db import engine
from models import CweOwaspMapping
from mitre_source import load_mitre_mitigations

mitre = load_mitre_mitigations()

with Session(engine) as session:
    missing = (
        session.query(CweOwaspMapping)
        .filter(CweOwaspMapping.remediation_workaround.is_(None))
        .order_by(CweOwaspMapping.cwe_id)
        .all()
    )
    print("CWE ที่ยังไม่มีคำแนะนำ:", len(missing))

    for m in missing:
        info = mitre.get(m.cwe_id)
        if info is None:
            print(f"\n{m.cwe_id}: ไม่มีในไฟล์ MITRE")
            continue
        print(f"\n{m.cwe_id} {info['name']}")
        print(f" mitigations ของตัวเอง: {len(info['mitigations'])} ตัวอักษร")
        print(f" แม่: {info['parents']}")
        for child in info["children"]:
            c = mitre[child]
            print(f" ลูก {child} {c['name']}: mitigations {len(c['mitigations'])} ตัวอักษร")