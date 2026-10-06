import re
from sqlalchemy.orm import Session
from db import engine
from models import CweOwaspMapping
from cwe_to_cheatsheet import parse_owasp_index, find_cheatsheet_with_fallback

test_ids = [
    "CWE-22", "CWE-74", "CWE-203", "CWE-248", "CWE-319", "CWE-330",
    "CWE-400", "CWE-405", "CWE-407", "CWE-415", "CWE-416", "CWE-436",
    "CWE-522", "CWE-524", "CWE-668", "CWE-749", "CWE-770", "CWE-787",
    "CWE-1050", "CWE-1333", "CWE-1357", "CWE-550",

]

index_data = parse_owasp_index("CheatSheetSeries/IndexTopTen.md")
with Session(engine) as session:
    for cat in ["A04:2021", "A08:2021", "A09:2021"]:
        print(f"\n{cat}: {index_data.get(cat, [])}")


    for cid in test_ids:
        m = session.get(CweOwaspMapping, cid)

        match = find_cheatsheet_with_fallback(m.description, m.owasp_top10_2021, index_data, "CheatSheetSeries/cheatsheets")

        verdict = f"✅ เจอ: {match}" if match else "❌ ยังไม่เจอ"
        print(f"{cid} | {m.description} | {verdict}")

    distinct_categories = session.query(CweOwaspMapping.owasp_top10_2021).distinct().all()
    for (cat,) in distinct_categories:
        print(repr(cat))