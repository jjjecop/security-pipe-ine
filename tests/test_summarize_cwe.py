import os 
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

with open("CheatSheetSeries/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md", "r", encoding="utf-8") as f:
    cheatsheet_content = f.read()

print("อ่านไฟล์สำเร็จ ความยาว:", len(cheatsheet_content), "ตัวอักษร")

prompt = f"""สรุปเนื้อหาต่อไปนี้เป็นคำแนะนำสั้นๆ ไม่เกิน 2 ประโยค ภาษาไทย
สำหรับนักพัฒนาที่ไม่สามารถ upgrade library ต้นเหตุได้ทันที
เน้นวิธีป้องกันที่ทำได้ที่ระดับ application/code เอง
ห้ามเพิ่มข้อมูลนอกเหนือจากเนื้อหาที่ให้มา:

{cheatsheet_content}
"""

response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents=prompt
)

print("\n--- คำแนะนำที่สรุปได้ ---")
print(response.text)