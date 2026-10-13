import os
from urllib.parse import urlsplit

SCAN_TYPES = ("sast", "dependency", "container", "dast")


def split_setting(value: str | None, separator: str) -> list[str]:
    return [item.strip() for item in (value or "").split(separator) if item.strip()]


def is_repo_allowed(repo_path: str, allowed_roots: list[str]) -> bool:
    # realpath แปลง .. และ shortcut ให้เป็น path จริงก่อนเทียบ
    # กันการหลบออกนอกโฟลเดอร์ เช่น C:\Allprojects\Targets\..\..\Users
    real = os.path.normcase(os.path.realpath(repo_path))
    for root in allowed_roots:
        real_root = os.path.normcase(os.path.realpath(root))
        try:
            if os.path.commonpath([real, real_root]) == real_root:
                return True
        except ValueError:
            # คนละไดรฟ์ เช่น C: กับ D: เทียบกันไม่ได้
            continue
    return False


def is_url_allowed(url: str, allowed_hosts: list[str]) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    return host in {h.lower() for h in allowed_hosts}


def resolve_scans(scans, repo_path=None, image=None, target_url=None) -> list[str]:
    if not scans:
        scans = []
        if repo_path:
            scans += ["sast", "dependency"]
        if image:
            scans.append("container")
        if target_url:
            scans.append("dast")

    if not scans:
        raise ValueError("ต้องระบุอย่างน้อยหนึ่งใน repo_path, image, target_url")
    if {"sast", "dependency"} & set(scans) and not repo_path:
        raise ValueError("sast/dependency ต้องระบุ repo_path")
    if "container" in scans and not image:
        raise ValueError("container ต้องระบุ image")
    if "dast" in scans and not target_url:
        raise ValueError("dast ต้องระบุ target_url")
    # ตัดตัวซ้ำแต่คงลำดับเดิม
    return list(dict.fromkeys(scans))