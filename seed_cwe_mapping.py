import json 

from sqlalchemy import create_engine
from sqlalchemy.orm import Session 

from models import CweOwaspMapping

from db import engine


with open("mappings/cwe_owasp_top10.json", "r", encoding="utf-8") as f:
    mapping_data = json.load(f)

print("จำนวน CWE ที่โหลดได้:", len(mapping_data))

with Session(engine) as session:
    inserted_count = 0
    for cwe_id, info in mapping_data.items():
        existing = session.get(CweOwaspMapping, cwe_id)
        if existing:
            existing.owasp_top10_2021 = info["owasp_top10_2021"]
            existing.description = info["description"]
            if info.get("remediation_workaround"):
                existing.remediation_workaround = info["remediation_workaround"]
            continue

        mapping_row = CweOwaspMapping(
            cwe_id=cwe_id,
            owasp_top10_2021=info["owasp_top10_2021"],
            description=info["description"],
            remediation_workaround=info.get("remediation_workaround")
        )
        session.add(mapping_row)
        inserted_count += 1

    session.commit()
    print("เพิ่ม mapping ใหม่เสร็จ:", inserted_count, "รายการ")