# ตรวจขั้นตอนค้นหา Cheat Sheet: ต้องไม่จับคู่จากส่วนของคำ ไม่เลือกไฟล์ที่ถูกยกเลิก และคืน None เมื่อไม่มั่นใจ
import pytest

from cheatsheet_lookup import MIN_FILE_BYTES, find_cheatsheet

BODY = "x" * (MIN_FILE_BYTES + 10)
INDEX = {
    "A01:2021": ["Authorization_Cheat_Sheet.md", "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md"],
    "A03:2021": ["Injection_Prevention_Cheat_Sheet.md", "Cross_Site_Scripting_Prevention_Cheat_Sheet.md"],
    "A07:2021": ["Authentication_Cheat_Sheet.md", "Session_Management_Cheat_Sheet.md"],
}


@pytest.fixture
def folder(tmp_path):
    names = [
        "Authorization", "Cross-Site_Request_Forgery_Prevention", "Injection_Prevention",
        "Cross_Site_Scripting_Prevention", "Authentication", "Session_Management",
        "C-Based_Toolchain_Hardening", "Secrets_Management", "Unvalidated_Redirects_and_Forwards",
        "Denial_of_Service", "Prototype_Pollution_Prevention", "HTTP_Headers",
    ]
    for name in names:
        (tmp_path / f"{name}_Cheat_Sheet.md").write_text(BODY, encoding="utf-8")
    # ไฟล์ที่ถูกยกเลิก เหลือแค่ข้อความชี้ไปฉบับใหม่
    (tmp_path / "Transport_Layer_Protection_Cheat_Sheet.md").write_text("deprecated, see TLS", encoding="utf-8")
    return str(tmp_path)


def test_hard_coded_credentials_does_not_match_hardening(folder):
    # ของเดิม: hard ไปตรงกับ Hardening
    result = find_cheatsheet("CWE-798", "Use of Hard-coded Credentials", "A07:2021 - x", INDEX, folder)
    assert result == "Secrets_Management_Cheat_Sheet.md"


def test_open_redirect_does_not_match_cross_site(folder):
    # ของเดิม: site ไปตรงกับ Cross-Site Request Forgery
    result = find_cheatsheet("CWE-601", "URL Redirection to Untrusted Site (Open Redirect)", "A01:2021 - x", INDEX, folder)
    assert result == "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md"


def test_partial_word_is_not_a_match(folder):
    # ไม่อยู่ใน DIRECT_MAP และไม่มีคำไหนตรงทั้งคำ ต้องไม่ได้ Hardening จากคำว่า hard
    assert find_cheatsheet("CWE-99999", "Hard Problem", "A05:2021 - x", INDEX, folder) is None


def test_category_match_uses_whole_words(folder):
    result = find_cheatsheet("CWE-99998", "Improper Authorization Check", "A01:2021 - x", INDEX, folder)
    assert result == "Authorization_Cheat_Sheet.md"


def test_outside_category_needs_two_words(folder):
    # นอกหมวดตรงคำเดียว (denial) ไม่พอ ต้องคืน None
    assert find_cheatsheet("CWE-99997", "Denial Something", "A09:2021 - x", INDEX, folder) is None
    # ตรงสองคำ (prototype, pollution) ใช้ได้
    result = find_cheatsheet("CWE-99996", "Prototype Pollution Variant", "A09:2021 - x", INDEX, folder)
    assert result == "Prototype_Pollution_Prevention_Cheat_Sheet.md"


def test_memory_cwe_has_no_cheatsheet(folder):
    # ไม่มี Cheat Sheet เรื่องหน่วยความจำ ต้องคืน None เพื่อให้ไปใช้ MITRE
    assert find_cheatsheet("CWE-416", "Use After Free", "A06:2021 - x", INDEX, folder) is None


def test_deprecated_stub_is_never_chosen(folder):
    result = find_cheatsheet("CWE-99995", "Transport Layer Protection", "A02:2021 - x", INDEX, folder)
    assert result is None


def test_direct_map_ignored_when_file_missing(tmp_path):
    (tmp_path / "Authentication_Cheat_Sheet.md").write_text(BODY, encoding="utf-8")
    # CWE-79 อยู่ใน DIRECT_MAP แต่ไม่มีไฟล์ ต้องไม่คืนชื่อไฟล์ที่ไม่มีอยู่จริง
    assert find_cheatsheet("CWE-79", "Cross-site Scripting (XSS)", "A03:2021 - x", {}, str(tmp_path)) is None
