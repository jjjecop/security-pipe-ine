import sys

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from db import engine
from models import Base

sys.stdout.reconfigure(encoding="utf-8")


def main():
    alembic_config = Config("alembic.ini")

    if inspect(engine).has_table("alembic_version"):
        # ฐานข้อมูลเดิม: ใช้ migration ตามปกติ
        print("พบฐานข้อมูลเดิม รัน migration ที่ยังไม่ได้รัน")
        command.upgrade(alembic_config, "head")
        return

    # ฐานข้อมูลใหม่ (เช่นใน CI หรือ Docker): migration แรกว่างเปล่า จึงสร้างตารางจาก models โดยตรง
    # แล้ว stamp ให้ alembic รู้ว่าเป็นเวอร์ชันล่าสุดแล้ว ไม่ต้องรัน migration เก่าซ้ำ
    print("ฐานข้อมูลใหม่ สร้างตารางทั้งหมดจาก models")
    Base.metadata.create_all(engine)
    command.stamp(alembic_config, "head")


if __name__ == "__main__":
    main()