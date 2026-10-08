import argparse
import json
import os
import sys

from sqlalchemy.orm import Session

from db import engine
from models import Finding, Project

sys.stdout.reconfigure(encoding="utf-8")


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


def verify_dependency_findings(session, project_id: int, installed_map: dict):
    dependency_findings = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .filter(Finding.location_type == "dependency")
        .filter(Finding.status == "open")
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
        elif claimed_version in actual_version:
            verified_count += 1
        else:
            mismatch_count += 1
            print(f"MISMATCH: {package_name} - Trivy บอก {claimed_version} แต่ไฟล์จริงคือ {actual_version}")

    print("\nยืนยันตรงกัน:", verified_count)
    print("เวอร์ชันไม่ตรงกัน:", mismatch_count)
    print("หาไม่เจอในไฟล์:", not_found_count)


def main():
    parser = argparse.ArgumentParser(description="เทียบเวอร์ชัน package ที่ Trivy รายงานกับ package-lock.json จริง")
    parser.add_argument("--project", required=True, help="ชื่อโปรเจกต์")
    parser.add_argument("--lockfile", help="path ของ package-lock.json (ค่าเริ่มต้น: ใน repo ของโปรเจกต์)")
    args = parser.parse_args()

    with Session(engine) as session:
        project = session.query(Project).filter(Project.name == args.project).first()
        if project is None:
            raise SystemExit(f"ไม่พบโปรเจกต์ '{args.project}'")

        lockfile_path = args.lockfile
        if lockfile_path is None:
            if not project.repo_url:
                raise SystemExit("โปรเจกต์นี้ไม่มี repo path กรุณาระบุ --lockfile")
            lockfile_path = os.path.join(project.repo_url, "package-lock.json")

        if not os.path.isfile(lockfile_path):
            raise SystemExit(f"ไม่พบไฟล์ {lockfile_path}")

        with open(lockfile_path, "r", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        installed_map = build_installed_packages_map(lockfile_data)
        print("อ่านไฟล์:", lockfile_path)
        print("จำนวน package ที่เจอ:", len(installed_map))

        verify_dependency_findings(session, project.id, installed_map)


if __name__ == "__main__":
    main()