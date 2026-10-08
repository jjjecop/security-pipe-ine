# Security Pipeline (VulnCompass)

ระบบสแกนช่องโหว่อัตโนมัติ รวมผลจาก 4 เครื่องมือ จัดลำดับความเสี่ยง และสร้างรายงานภาษาไทย

| ประเภท | เครื่องมือ | สแกนอะไร |
|---|---|---|
| SAST | Semgrep | source code
| Dependency | Trivy fs | library ใน package-lock.json |
| Container | Trivy image | Do
| DAST | OWASP ZAP | เว็บที่รันอยู่จริง |

## การทำงาน

1. สแกนด้วยเครื่องมือที่เลือก
2. แปลงผลเป็นรูปแบบเดียวกัน แล้วตัดตั
3. บันทึกลง PostgreSQL ช่องโหว่ที่สแกนรอบใหม่แล้วไม่เจอจะถูกเปลี่ยนเป็น `fixed`
4. จับคู่ CWE กับ OWASP Top 10 และ
5. สร้างรายงาน HTML และ PDF พร้อมคำแนะนำการแก้ไข

## สิ่งที่ต้องติดตั้งก่อน

- Python 3.12 ขึ้นไป
- Docker Desktop
- Trivy (https://trivy.dev)
- GTK3 runtime สำหรับ WeasyPrin

## ติดตั้ง

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt
```

สร้างไฟล์ `.env` ที่ root ของโปรเจ

```
POSTGRES_USER=secpipeline
POSTGRES_PASSWORD=ตั้งรหัสผ่านเอง
POSTGRES_DB=secpipeline
GEMINI_API_KEY=ใส่ API key ของ
```

> ห้าม commit ไฟล์ `.env` เด็ดขาด (อยู่ใน `.gitignore` แล้ว)

เปิดฐานข้อมูลและสร้างตาราง:

```powershell
docker compose up -d
alembic upgrade head
python seed_cwe_mapping.py
```

## การใช้งาน

ทุกครั้งที่เปิดเครื่องใหม่ ให้เปิด Docker Desktop แล้วรัน:

```powershell
docker compose up -d
```

สแกนครบทั้ง 4 แบบแล้วสร้างรายงาน:

```powershell
python run_pipeline.py --proje
  --repo C:\Allprojects\Targets\NodeGoat `
  --image nodegoat:latest `
  --url http://host.docker.internal:4000
```
                                                                                         เลือกสแกนบางแบบ:
                                                                                         ```powershell
python run_pipeline.py --project NodeGoat --repo C:\Allprojects\Targets\NodeGoat --scans sast
```

รายงานจะอยู่ที่ `reports\<ชื่อโปรเจกต์>_<วันเวลา>\`
- `dashboard.html` เปิดในเบราว์เ
- `security_report.pdf`

สร้างรายงานใหม่จากข้อมูลเดิมโดยไม่ต้องสแกน:

```powershell
python generate_report.py --pr
```

ดูตัวเลือกทั้งหมด:

```powershell
python run_pipeline.py --help
```

> ถ้าเว็บที่จะสแกน DAST รันบนเครื่องตัวเอง ให้ใช้ `host.docker.internal` แทน `localhost` เพราะ ZAP
รันอยู่ใน Docker

## ทดสอบ

```powershell
pytest -v
```

## Backup ฐานข้อมูล

```powershell
docker exec secpipeline-postgres pg_dump -U secpipeline -d secpipeline -Fc -f /tmp/secpipeline.dump
docker cp secpipeline-postgres:/tmp/secpipeline.dump backups\secpipeline_YYYYMMDD.dump
```

ไฟล์ backup มีข้อมูลช่องโหว่อยู่ข้างใน  `.gitignore` แล้ว)

## แก้ปัญหาที่พบบ่อย

| อาการ | สาเหตุ | วิธีแก้ |
|---|---|---|
| `Connection refused` port 54ocker Desktop แล้วรัน `dockercompose up -d` |
| Semgrep ขึ้น `CERTIFICATE_VERIorton) ดักการเชื่อมต่อ HTTPS | สร้าง`ca-bundle.pem` จาก certifi รวมกับ cert ของ antivirus แล้วตั้ง `REQUESTS_CA_BUNDLE` และ
`SSL_CERT_FILE` ใน `.env` |
| ภาษาไทยเป็นตัวอ่านไม่ออกใน PowerShell | console ไม่ใช่ UTF-8 | เปิดไฟล์ด้วย VS Code แทน
`Get-Content` |

## โครงสร้างโปรเจกต์

| ไฟล์/โฟลเดอร์ | หน้าที่ |
|---|---|
| `run_pipeline.py` | จุดเริ่มต้น
| `scanners/` | เรียก Semgrep, Trivy, ZAP |
| `normalizer.py` | แปลงผลแต่ละingerprint |
| `save_findings.py` | บันทึกผล ตัดตัวซ้ำ และติดตามสถานะ open/fixed |
| `risk_scoring.py` | คำนวณ ri
| `apply_cwe_mapping.py` | จับคู่ CWE กับ OWASP Top 10 |
| `generate_report.py` | สร้างร
| `generate_remediation.py` | สร้างคำแนะนำการแก้ไขด้วย Gemini |
| `verify_findings.py` | เทียบผจริง |
| `models.py`, `alembic/` | โครงสร้างตารางในฐานข้อมูล |
| `templates/` | แม่แบบรายงาน |
| `tests/` | pytest |
| `scripts/` | สคริปต์ทดลองเครื่อง