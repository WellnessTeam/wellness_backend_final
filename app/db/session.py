from sqlalchemy import event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.sql import text
from typing import AsyncGenerator
from core.config import DATABASE_URL, TEST_DATABASE_URL  # config.py에서 환경 변수 가져오기
import os
from pytz import timezone
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경 변수에서 데이터베이스 URL 및 타임존 가져오기
DATABASE_URL = os.getenv("DATABASE_URL").replace("postgresql://", "postgresql+asyncpg://")
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL").replace("postgresql://", "postgresql+asyncpg://")
TIMEZONE = os.getenv("TIMEZONE", "Asia/Seoul")  # 기본적으로 'Asia/Seoul'


# SQLAlchemy 비동기 엔진 생성
engine = create_async_engine(DATABASE_URL, echo=True)
test_engine = create_async_engine(TEST_DATABASE_URL, echo=True)

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
AsyncTestSessionLocal = sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False
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

# Test DB 연결 세션 함수
async def get_test_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncTestSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# 테이블 생성
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def init_test_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
