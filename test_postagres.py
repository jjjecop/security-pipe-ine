from sqlalchemy import create_engine
from models import Base

engine = create_engine("postgresql+psycopg2://secpipeline:devpassword123@localhost:5432/secpipeline")

Base.metadata.create_all(engine)

print("เชื่อมต่อ Postgres และสร้างตารางสำเร็จ!")