from sqlalchemy import event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.sql import text
from typing import AsyncGenerator
from core.config import DATABASE_URL # config.py에서 환경 변수 가져오기
import os
from pytz import timezone
from dotenv import load_dotenv
from core.config import DATABASE_URL, TIMEZONE


# SQLAlchemy 비동기 엔진 생성
engine = create_async_engine(DATABASE_URL, echo=True)


# 타임존 설정을 위한 이벤트 리스너
@event.listens_for(engine.sync_engine, "connect")
def set_timezone(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute(f"SET timezone TO '{TIMEZONE}'")
    cursor.close()

# 비동기 세션 생성
AsyncSessionLocal = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


# Base 클래스 생성
Base = declarative_base()

# DB 연결 세션 함수
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# 테이블 생성
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

