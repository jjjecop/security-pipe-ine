import subprocess
import json


class ScannerError(Exception):
    pass


def run_tool(cmd: list[str], ok_exit_codes: tuple[int, ...] = (0,), timeout: int = 1800) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        raise ScannerError(f"ไม่พบโปรแกรม '{cmd[0]}' กรุณาติดตั้งและเพิ่มใน PATH")
    except subprocess.TimeoutExpired:
        raise ScannerError(f"'{cmd[0]}' ทำงานเกิน {timeout} วินาที")

    if result.returncode not in ok_exit_codes:
        stderr_tail = (result.stderr or "").strip()[-1000:]
        raise ScannerError(f"'{cmd[0]}' จบด้วย exit code {result.returncode}: {stderr_tail}")

    return result


def parse_json_output(tool_name: str, text: str) -> dict:
    if not text or not text.strip():
        raise ScannerError(f"{tool_name} ไม่ได้ส่งผลลัพธ์ออกมา")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ScannerError(f"อ่าน JSON จาก {tool_name} ไม่ได้: {e}")
