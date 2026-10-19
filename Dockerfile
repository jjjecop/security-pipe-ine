# image เดียวใช้ทั้ง API และ worker (worker ต้องมี semgrep, trivy และไลบรารีทำ PDF)
FROM python:3.14.8-slim

# PYTHONUNBUFFERED ให้ print ขึ้นใน docker compose logs ทันที ไม่ค้างใน buffer
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ไลบรารีที่ WeasyPrint ใช้สร้าง PDF + ฟอนต์ไทย และ curl สำหรับโหลด Trivy
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 fonts-thai-tlwg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ใช้สคริปต์เดียวกับ CI: ล็อกเวอร์ชันและตรวจ SHA-256 ก่อนติดตั้ง
COPY scripts/install_trivy.sh /tmp/install_trivy.sh
RUN bash /tmp/install_trivy.sh && rm /tmp/install_trivy.sh

WORKDIR /app

# copy requirements ก่อนโค้ด ถ้าแก้แค่โค้ด Docker จะใช้ layer ที่ติดตั้งไว้แล้วซ้ำ ไม่ต้อง pip install ใหม่
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ไม่รันเป็น root ถ้ามีคนเจาะเข้ามาได้ จะทำได้แค่สิทธิ์ของ user นี้
RUN useradd --create-home --uid 1000 app \
    && mkdir -p reports /home/app/.cache/trivy \
    && chown -R app reports /home/app/.cache
USER app

EXPOSE 8000
# 0.0.0.0 ใน container แปลว่ารับจาก network ภายในของ Docker เท่านั้น เพราะไม่ได้เปิด port 8000 ออกไปที่เครื่อง
# --proxy-headers อ่าน IP จริงของผู้ใช้จาก nginx เพื่อให้การจำกัดการ login นับแยกตามคน
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]