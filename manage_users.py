import argparse
import getpass
import re
import sys

from sqlalchemy.orm import Session

from auth import hash_password, password_problem
from db import engine
from models import User

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def ask_new_password() -> str:
    # getpass ซ่อนสิ่งที่พิมพ์ และรหัสผ่านไม่ไปค้างอยู่ในประวัติคำสั่งของ terminal
    while True:
        password = getpass.getpass("รหัสผ่านใหม่: ")
        problem = password_problem(password)
        if problem:
            print(problem)
            continue
        if getpass.getpass("พิมพ์รหัสผ่านอีกครั้ง: ") != password:
            print("รหัสผ่านไม่ตรงกัน ลองใหม่")
            continue
        return password


def get_user_or_exit(session, username: str) -> User:
    user = session.query(User).filter(User.username == username).first()
    if user is None:
        raise SystemExit(f"ไม่พบ user '{username}'")
    return user


def create_user(session, username: str):
    if not USERNAME_PATTERN.match(username):
        raise SystemExit("username ใช้ได้เฉพาะ A-Z a-z 0-9 _ . - ยาว 3-50 ตัว")
    if session.query(User).filter(User.username == username).first():
        raise SystemExit(f"มี user '{username}' อยู่แล้ว")
    user = User(username=username, password_hash=hash_password(ask_new_password()))
    session.add(user)
    session.commit()
    print(f"สร้าง user '{username}' แล้ว")


def change_password(session, username: str):
    user = get_user_or_exit(session, username)
    user.password_hash = hash_password(ask_new_password())
    session.commit()
    print(f"เปลี่ยนรหัสผ่านของ '{username}' แล้ว")


def set_active(session, username: str, active: bool):
    user = get_user_or_exit(session, username)
    user.is_active = active
    session.commit()
    print(f"{'เปิด' if active else 'ปิด'}บัญชี '{username}' แล้ว")


def list_users(session):
    users = session.query(User).order_by(User.username).all()
    if not users:
        print("ยังไม่มี user")
    for user in users:
        status = "ใช้งานได้" if user.is_active else "ปิดอยู่"
        last_login = user.last_login_at.strftime("%Y-%m-%d %H:%M") if user.last_login_at else "-"
        print(f"{user.username:20} {status:10} login ล่าสุด: {last_login}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="จัดการ user สำหรับเข้าหน้าเว็บ")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("create", "สร้าง user ใหม่"),
        ("passwd", "เปลี่ยนรหัสผ่าน"),
        ("disable", "ปิดบัญชี (เข้าระบบไม่ได้ แต่ข้อมูลยังอยู่)"),
        ("enable", "เปิดบัญชีที่ปิดไว้"),
    ]:
        commands.add_parser(name, help=help_text).add_argument("username")
    commands.add_parser("list", help="แสดง user ทั้งหมด")
    args = parser.parse_args()

    with Session(engine) as session:
        if args.command == "create":
            create_user(session, args.username)
        elif args.command == "passwd":
            change_password(session, args.username)
        elif args.command == "disable":
            set_active(session, args.username, False)
        elif args.command == "enable":
            set_active(session, args.username, True)
        elif args.command == "list":
            list_users(session)


if __name__ == "__main__":
    main()