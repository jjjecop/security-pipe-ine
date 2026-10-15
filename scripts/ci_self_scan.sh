#!/usr/bin/env bash
# ให้ VulnCompass สแกนโค้ดของตัวเอง ใช้ทั้งใน GitHub Actions และตอนทดสอบใน Docker
# ต้องตั้ง POSTGRES_* ไว้ก่อน และต้องมี semgrep กับ trivy ใน PATH
set -euo pipefail

FAIL_ON="${FAIL_ON:-critical}"

python init_db.py
python seed_cwe_mapping.py
python run_pipeline.py \
  --project VulnCompass \
  --repo . \
  --scans sast,dependency \
  --fail-on "$FAIL_ON"