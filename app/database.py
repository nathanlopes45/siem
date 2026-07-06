import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()

# Wait for database to be ready
for i in range(10):
    try:
        conn = engine.connect()
        conn.close()
        print("Database connected!")
        break
    except Exception:
        print("Database not ready, retrying in 3 seconds...")
        time.sleep(3)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()