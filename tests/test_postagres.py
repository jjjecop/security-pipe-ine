from sqlalchemy import create_engine
from models import Base
from db import engine

Base.metadata.create_all(engine)

print("เชื่อมต่อ Postgres และสร้างตารางสำเร็จ!")