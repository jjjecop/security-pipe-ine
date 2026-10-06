import os, time
from google import genai 
from dotenv import load_dotenv

from db import engine 
from sqlalchemy.orm import Session 
from models import CweOwaspMapping

from cwe_to_cheatsheet import parse_owasp_index, find_cheatsheet_with_fallback, build_document_frequency, find_best_content_match
from mitre_source import load_mitre_mitigations, collect_children_mitigations


load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

CHEATSHEETS_FOLDER = "CheatSheetSeries/cheatsheets"
INDEX_FILE = "CheatSheetSeries/IndexTopTen.md"

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
NOT_COVERED = "NOT_COVERED"

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
    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
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
    response = client.models.generate_content(model="gemini-3.6-flash", contents=prompt)
    return response.text.strip()

with Session(engine) as session:
    index_data = parse_owasp_index(INDEX_FILE)
    df, n_docs, file_contents = build_document_frequency(CHEATSHEETS_FOLDER)
    mitre = load_mitre_mitigations()

    all_mappings = session.query(CweOwaspMapping).order_by(CweOwaspMapping.cwe_id).all()

    print("จำนวน CWE ทั้งหมดในฐานข้อมูล", len(all_mappings))

    success_count = 0
    skip_already_done = 0
    skip_no_cheatsheet = 0
    skip_not_covered = 0
    skip_error = 0

    no_cheatsheet_ids = []
    needs_manual_ids = []

    for mapping in all_mappings:
        if mapping.remediation_workaround is not None:
            skip_already_done += 1
            continue

        print(f"\nกำลังประมวลผล {mapping.cwe_id} ({mapping.description})...")

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

        summary = None
        source = None 

        try: 
            if cheatsheet_file is not None:
                file_path = os.path.join(CHEATSHEETS_FOLDER, cheatsheet_file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                summary = summarize_with_gemini(content, mapping.cwe_id, mapping.description)
                time.sleep(13)
                if summary is None: 
                    print(f" Gemini ยืนยันว่า {cheatsheet_file} ไม่ครอบคลุม {mapping.cwe_id}")
                else: 
                    source = cheatsheet_file 
            else:
                print(f" ไม่พบ Cheat Sheet ที่ตรงกัน ({mapping.cwe_id})")

            if summary is None:
                mitre_info = mitre.get(mapping.cwe_id)
                if mitre_info and mitre_info["mitigations"]:
                    print(" กำลังลองใช้ Potential Mitigations จาก MITRE...")
                    summary = summarize_with_gemini(mitre_info["mitigations"], mapping.cwe_id, mapping.description)
                    time.sleep(13)
                    if summary is not None:
                        source = "MITRE CWE"
                else: 
                    print(f" MITRE ไม่มี Potential Mitigations สำหรับ {mapping.cwe_id}")

            if summary is None:
                children_text, used_children = collect_children_mitigations(mitre, mapping.cwe_id)
                if children_text:
                    print(f" กำลังลองใช้ mitigations ของ CWE ลูก: {', '.join(used_children)}...")
                    note = (
                        f"เอกสารด้านล่างเป็นวิธีลดความเสี่ยงของช่องโหว่ย่อยที่เป็นรูปแบบเฉพาะของ {mapping.cwe_id} "
                        f"ให้สรุปเฉพาะหลักการร่วมที่ใช้ป้องกัน {mapping.cwe_id} ได้ทั่วไป ไม่ใช่วิธีเฉพาะของช่องโหว่ย่อยตัวใดตัวหนึ่ง"
                    )
                    summary = summarize_with_gemini(children_text, mapping.cwe_id, mapping.description, context_note=note)
                    time.sleep(13)
                    if summary is not None:
                        source = f"MITRE CWE (จาก CWE ลูก: {', '.join(used_children)})"
                else:
                    print(f" ไม่มี CWE ลูกที่มี mitigations สำหรับ {mapping.cwe_id}")

            if summary is None:
                skip_not_covered += 1
                needs_manual_ids.append(mapping.cwe_id)
                continue

            mapping.remediation_workaround = summary
            session.commit()
            success_count += 1
            print(f" สำเร็จ (แหล่ง: {source}): {summary[:80]}...")
        except Exception as e:
             
            error_str = str(e)
            if "RESOURCE_EXHAUSTED" in error_str:
                print(f"\n⚠️  โควตา Gemini API หมด (หยุดที่ {mapping.cwe_id})")
                print(f" detail {error_str}")
                skip_error += 1 
                break
            print(f" เกิดข้อผิดพลาด ({mapping.cwe_id}): {e}")
            skip_error +=1

 

    print("\n\n=== สรุปผลลัพธ์ ===")
    print("สำเร็จ:", success_count)
    print("ข้าม:, (มี remediation อยู่เเล้ว):", skip_already_done)
    print("ข้าม (ไม่พบ cheatsheet):", skip_no_cheatsheet)
    print("ข้าม (error/API)", skip_error)
    print("ข้าม (Gemini ยืนยันว่าไฟล์ไม่ครอบคลุม):", skip_not_covered)

    if no_cheatsheet_ids:
        print("\nรายการ CWE ที่ไม่พบ Cheat Sheet ที่ตรงกัน")
        for cwe_id in no_cheatsheet_ids:
            print(" -", cwe_id)
            
    if needs_manual_ids:
        print("\nCWE ที่ต้องเขียนคำแนะนำเอง (ผ่านทุกชั้นแล้วไม่มีเอกสารที่ตรง):")
        for cwe_id in needs_manual_ids:
            print(" -", cwe_id)