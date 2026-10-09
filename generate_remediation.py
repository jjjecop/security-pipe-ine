import argparse
import os
import sys
import time

from dotenv import load_dotenv
from google import genai
from sqlalchemy.orm import Session

from db import engine
from models import CweOwaspMapping, Finding, Project
from apply_cwe_mapping import normalize_cwe_id
from cwe_to_cheatsheet import parse_owasp_index, find_cheatsheet_with_fallback, build_document_frequency, find_best_content_match
from mitre_source import load_mitre_mitigations, collect_children_mitigations


load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHEATSHEETS_FOLDER = os.path.join(BASE_DIR, "CheatSheetSeries", "cheatsheets")
INDEX_FILE = os.path.join(BASE_DIR, "CheatSheetSeries", "IndexTopTen.md")
MITRE_CSV = os.path.join(BASE_DIR, "mitre", "1000.csv")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
NOT_COVERED = "NOT_COVERED"
# Gemini free tier จำกัดจำนวนครั้งต่อนาที เลยต้องรอระหว่างแต่ละครั้ง
GEMINI_DELAY_SECONDS = 13

_client = None


def get_client():
    # สร้าง client ตอนจะใช้จริง ไม่ใช่ตอน import จะได้ import ไฟล์นี้ได้แม้ไม่มี API key
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("ไม่พบ GEMINI_API_KEY ใน .env")
        _client = genai.Client(api_key=api_key)
    return _client


def summarize_with_gemini(cheatsheet_content: str, cwe_id: str, cwe_name: str, context_note: str = "") -> str | None:
    prompt = f"""ช่องโหว่ที่ต้องการคำแนะนำ: {cwe_id} {cwe_name} {context_note}
อ่านเอกสารอ้างอิงด้านล่าง แล้วสรุปเฉพาะวิธีป้องกันช่องโหว่นี้โดยตรง
เป็นภาษาไทยไม่เกิน 2-3 ประโยค สำหรับนักพัฒนาที่ยัง upgrade library ต้นเหตุไม่ได้
เน้นวิธีที่ทำได้ที่ระดับ application/code ใช้ข้อความธรรมดา ไม่ใช้ markdown
ห้ามเพิ่มข้อมูลที่ไม่มีในเอกสาร
ถ้าเอกสารไม่ได้อธิบายวิธีป้องกันช่องโหว่นี้โดยตรง (แค่มีคำคล้ายกัน หรือพูดถึงผ่านๆ) ให้ตอบคำเดียวว่า {NOT_COVERED}

เอกสาร:
{cheatsheet_content}
"""
    response = get_client().models.generate_content(model=GEMINI_MODEL, contents=prompt)
    time.sleep(GEMINI_DELAY_SECONDS)
    text = (response.text or "").strip()
    if not text or NOT_COVERED in text:
        return None
    return text


def ask_gemini_to_pick(description, candidates):
    prompt = f"""ต่อไปนี้คือคำอธิบายช่องโหว่ความปลอดภัย (CWE) และรายชื่อไฟล์ cheat sheet ที่อาจเกี่ยวข้อง
เลือกไฟล์ที่ตรงประเด็นเรื่องนี้ที่สุดเพียงไฟล์เดียว
ถ้าไม่มีไฟล์ไหนเกี่ยวข้องกับช่องโหว่นี้จริงๆ ให้ตอบว่า NONE
ตอบแค่ชื่อไฟล์เป๊ะๆ ตามที่เห็นในรายการ หรือคำว่า NONE เท่านั้น ห้ามอธิบายเพิ่มเติม

คำอธิบายช่องโหว่: {description}

รายชื่อไฟล์:
{chr(10).join(candidates)}
"""
    response = get_client().models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return response.text.strip()


def remediate_one(mapping, index_data, df, n_docs, file_contents, mitre):
    # ลองหาคำแนะนำทีละแหล่ง: Cheat Sheet -> MITRE -> MITRE ของ CWE ลูก
    cheatsheet_file = find_cheatsheet_with_fallback(
        mapping.description,
        mapping.owasp_top10_2021,
        index_data,
        CHEATSHEETS_FOLDER,
    )
    if cheatsheet_file is None:
        print(f" ไม่พบใน Index/ชื่อไฟล์ ({mapping.cwe_id}) กำลังคำนวณจากเนื้อหาแบบ IDF...")
        best_file, score = find_best_content_match(mapping.description, df, n_docs, file_contents)
        if best_file:
            cheatsheet_file = best_file
            print(f" เจอจากเนื้อหา (score={score:.1f}): {best_file}")
        else:
            print(f"   คะแนนสูงสุดที่เจอ: {score:.1f} (ต่ำกว่าเกณฑ์จึงไม่ใช้)")

    if cheatsheet_file is not None:
        with open(os.path.join(CHEATSHEETS_FOLDER, cheatsheet_file), "r", encoding="utf-8") as f:
            content = f.read()
        summary = summarize_with_gemini(content, mapping.cwe_id, mapping.description)
        if summary is not None:
            return summary, cheatsheet_file
        print(f" Gemini ยืนยันว่า {cheatsheet_file} ไม่ครอบคลุม {mapping.cwe_id}")
    else:
        print(f" ไม่พบ Cheat Sheet ที่ตรงกัน ({mapping.cwe_id})")

    mitre_info = mitre.get(mapping.cwe_id)
    if mitre_info and mitre_info["mitigations"]:
        print(" กำลังลองใช้ Potential Mitigations จาก MITRE...")
        summary = summarize_with_gemini(mitre_info["mitigations"], mapping.cwe_id, mapping.description)
        if summary is not None:
            return summary, "MITRE CWE"
    else:
        print(f" MITRE ไม่มี Potential Mitigations สำหรับ {mapping.cwe_id}")

    children_text, used_children = collect_children_mitigations(mitre, mapping.cwe_id)
    if children_text:
        print(f" กำลังลองใช้ mitigations ของ CWE ลูก: {', '.join(used_children)}...")
        note = (
            f"เอกสารด้านล่างเป็นวิธีลดความเสี่ยงของช่องโหว่ย่อยที่เป็นรูปแบบเฉพาะของ {mapping.cwe_id} "
            f"ให้สรุปเฉพาะหลักการร่วมที่ใช้ป้องกัน {mapping.cwe_id} ได้ทั่วไป ไม่ใช่วิธีเฉพาะของช่องโหว่ย่อยตัวใดตัวหนึ่ง"
        )
        summary = summarize_with_gemini(children_text, mapping.cwe_id, mapping.description, context_note=note)
        if summary is not None:
            return summary, f"MITRE CWE (จาก CWE ลูก: {', '.join(used_children)})"
    else:
        print(f" ไม่มี CWE ลูกที่มี mitigations สำหรับ {mapping.cwe_id}")

    return None, None


def get_project_cwe_ids(session, project_id: int) -> set[str]:
    rows = (
        session.query(Finding.cwe_id)
        .filter(Finding.project_id == project_id)
        .filter(Finding.status == "open")
        .filter(Finding.cwe_id.isnot(None))
        .distinct()
        .all()
    )
    cwe_ids = set()
    for (cwe_id,) in rows:
        normalized = normalize_cwe_id(cwe_id)
        if normalized:
            cwe_ids.add(normalized)
    return cwe_ids


def generate_remediation(session, cwe_ids: set[str] | None = None):
    query = session.query(CweOwaspMapping).filter(CweOwaspMapping.remediation_workaround.is_(None))
    if cwe_ids is not None:
        query = query.filter(CweOwaspMapping.cwe_id.in_(cwe_ids))
    pending = query.order_by(CweOwaspMapping.cwe_id).all()

    print("CWE ที่ยังไม่มีคำแนะนำ:", len(pending))
    if not pending:
        return

    if not os.path.isdir(CHEATSHEETS_FOLDER):
        raise RuntimeError(
            f"ไม่พบโฟลเดอร์ {CHEATSHEETS_FOLDER} "
            "ให้ clone ก่อน: git clone https://github.com/OWASP/CheatSheetSeries"
        )

    index_data = parse_owasp_index(INDEX_FILE)
    df, n_docs, file_contents = build_document_frequency(CHEATSHEETS_FOLDER)
    mitre = load_mitre_mitigations(MITRE_CSV)

    success_count = 0
    error_count = 0
    needs_manual_ids = []

    for mapping in pending:
        print(f"\nกำลังประมวลผล {mapping.cwe_id} ({mapping.description})...")
        try:
            summary, source = remediate_one(mapping, index_data, df, n_docs, file_contents, mitre)
        except Exception as e:
            error_count += 1
            if "RESOURCE_EXHAUSTED" in str(e):
                print(f"\nโควตา Gemini API หมด (หยุดที่ {mapping.cwe_id})")
                print(f" detail {e}")
                break
            print(f" เกิดข้อผิดพลาด ({mapping.cwe_id}): {e}")
            continue

        if summary is None:
            needs_manual_ids.append(mapping.cwe_id)
            continue

        mapping.remediation_workaround = summary
        session.commit()
        success_count += 1
        print(f" สำเร็จ (แหล่ง: {source}): {summary[:80]}...")

    print("\n=== สรุปผลลัพธ์ ===")
    print("สำเร็จ:", success_count)
    print("ข้าม (error/API):", error_count)
    print("ข้าม (ไม่มีเอกสารที่ตรง):", len(needs_manual_ids))

    if needs_manual_ids:
        print("\nCWE ที่ต้องเขียนคำแนะนำเอง (ผ่านทุกชั้นแล้วไม่มีเอกสารที่ตรง):")
        for cwe_id in needs_manual_ids:
            print(" -", cwe_id)


def main():
    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="ให้ Gemini เขียนคำแนะนำการแก้ไขสำหรับ CWE ที่ยังไม่มี")
    parser.add_argument("--project", help="ทำเฉพาะ CWE ที่พบในโปรเจกต์นี้ (ค่าเริ่มต้น: ทุก CWE ในฐานข้อมูล)")
    args = parser.parse_args()

    with Session(engine) as session:
        cwe_ids = None
        if args.project:
            project = session.query(Project).filter(Project.name == args.project).first()
            if project is None:
                raise SystemExit(f"ไม่พบโปรเจกต์ '{args.project}'")
            cwe_ids = get_project_cwe_ids(session, project.id)
        generate_remediation(session, cwe_ids=cwe_ids)


if __name__ == "__main__":
    main()