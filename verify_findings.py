import json

from db import engine
from sqlalchemy.orm import Session

from models import Finding


with open(r"C:\Allprojects\Targets\NodeGoat\package-lock.json", "r", encoding="utf-8") as f:
    lockfile_data = json.load(f)

print("อ่านไฟล์สำเร็จ, key ระดับบนสุด:", lockfile_data.keys())    

def build_installed_packages_map(lockfile_data: dict) -> dict:
    packages = lockfile_data.get("packages", {})
    result = {}

    for path, info in packages.items():
        if not path.startswith("node_modules/"):
            continue

        package_name = path.split("node_modules/")[-1]
        version = info.get("version")

        if package_name and version:
            if package_name not in result:
                result[package_name] = set()
            result[package_name].add(version)

    return result


installed_map = build_installed_packages_map(lockfile_data)
print("จำนวน package ที่เจอ:", len(installed_map))
print("ตัวอย่าง mixin-deep:", installed_map.get("mixin-deep"))

with Session(engine) as session:
    dependency_findings = (
        session.query(Finding)
        .filter(Finding.location_type == "dependency")
        .all()
    )

    print("\nจำนวน Finding ประเภท dependency:", len(dependency_findings))

    verified_count = 0
    mismatch_count = 0
    not_found_count = 0

    for finding in dependency_findings:
        dep_info = finding.location.get("dependency", {})
        package_name = dep_info.get("package_name")
        claimed_version = dep_info.get("installed_version")

        actual_version = installed_map.get(package_name)

        if actual_version is None:
            not_found_count += 1 
        elif  claimed_version in actual_version:
            verified_count += 1
        else:
            mismatch_count += 1 
            print(f"MISMATCH: {package_name} - Trivy บอก {claimed_version} แต่ไฟล์จริงคือ {actual_version}")

    print("\nยืนยันตรงกัน:", verified_count)
    print("เวอร์ชันไม่ตรงกัน:", mismatch_count)
    print("หาไม่เจอในไฟล์:", not_found_count)