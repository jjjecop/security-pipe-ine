from sqlalchemy import create_engine
from models import Base

engine = create_engine("sqlite:///test.db")

Base.metadata.create_all(engine)

print("สร้างตารางสำเร็จ")