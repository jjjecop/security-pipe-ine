import os
import shutil
import tempfile

from scanners.runner import run_tool, parse_json_output, ScannerError


def run_zap_baseline_scan(target_url: str) -> dict:
    output_file = "zap_results.json"
    # ใช้โฟลเดอร์ชั่วคราวใหม่ทุกครั้ง เพื่อไม่ให้อ่านผลสแกนรอบเก่าที่ค้างอยู่
    work_dir = tempfile.mkdtemp(prefix="zap_")

    try:
        # zap-baseline: 0 = ผ่าน, 1 = มี FAIL, 2 = มี WARN, 3 = error
        run_tool(
            [
                "docker", "run", "--rm",
                "-v", f"{work_dir}:/zap/wrk/:rw",
                "zaproxy/zap-stable",
                "zap-baseline.py",
                "-t", target_url,
                "-J", output_file,
            ],
            ok_exit_codes=(0, 1, 2),
        )

        result_path = os.path.join(work_dir, output_file)
        if not os.path.exists(result_path):
            raise ScannerError("ZAP ไม่ได้สร้างไฟล์ผลลัพธ์")

        with open(result_path, "r", encoding="utf-8") as f:
            return parse_json_output("zap", f.read())
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
