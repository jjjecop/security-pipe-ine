from datetime import UTC, datetime, timedelta

from models import utc_now


def test_utc_now_matches_the_old_utcnow_format():
    # ฐานข้อมูลเก็บเวลาแบบไม่มี timezone และหน้าเว็บเติม Z (UTC) เองตอนแสดงผล จึงต้องไม่มี tzinfo
    now = utc_now()
    assert now.tzinfo is None
    assert abs(now - datetime.now(UTC).replace(tzinfo=None)) < timedelta(seconds=5)
