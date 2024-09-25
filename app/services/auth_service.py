from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import pytz
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from db.session import get_db
from db.models import Auth, User
from schemas.auth import Token, TokenData
from core.logging import logger
import os
from sqlalchemy import text
from core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS


# 토큰을 Bearer 방식으로 받아오는 OAuth2 스키마
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Access 토큰 생성
def create_access_token(data: dict, expires_delta: int):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)  # UTC 시간 사용
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Access Token 생성 완료: {token}")
    return token

# Refresh 토큰 생성
def create_refresh_token(data: dict, expires_delta: int):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=expires_delta)  # UTC 시간 사용
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Refresh Token 생성 완료: {token}")
    return token

# 엑세스 토큰 만료 확인 함수
def is_access_token_expired(expiry_time: datetime):
    return datetime.utcnow() > expiry_time  # UTC 시간 기준


# 토큰 검증 함수
def verify_refresh_token(token: str, expiry_time: datetime):
    current_time_utc = datetime.now(pytz.UTC).replace(tzinfo=pytz.UTC)  # UTC 시간으로 변환
    
    if expiry_time.tzinfo is None:
        expiry_time = expiry_time.replace(tzinfo=pytz.UTC)
        
    if current_time_utc > expiry_time:
        logger.error("Refresh token expired based on expiry_time in DB")
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.info(f"Refresh Token validated successfully: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"Refresh token validation failed: {e}")
        raise HTTPException(
            status_code=401, detail="Refresh token invalid or expired")


# 비동기 토큰 검증 및 유저 반환 함수
# 비동기 토큰 검증 및 유저 반환 함수
async def validate_token(db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    # 토큰을 확인하는 로그 추가
    logger.info(f"Received token: {token}")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 데이터베이스에서 토큰 조회 (비동기)
    auth_entry = await db.execute(
        text("SELECT * FROM auth WHERE access_token = :token"),  # text 함수 사용
        {"token": token}
    )
    auth_entry = auth_entry.fetchone()

    if auth_entry is None:
        # 토큰 조회 실패 시 로그 기록
        logger.error(f"Token not found in the database: {token}")
        raise credentials_exception

    # 토큰 만료 여부 확인
    if auth_entry.access_expired_at < datetime.utcnow():
        # 만료된 토큰일 경우 로그 기록
        logger.error(f"Token expired: {token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 여기서 User 객체 반환
    user_result = await db.execute(
        text("SELECT * FROM user_info WHERE id = :user_id"),  # text 함수 사용
        {"user_id": auth_entry.user_id}
    )
    user = user_result.fetchone()

    if user is None:
        logger.error(f"User not found for token: {token}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.info(f"Returning user object: {user} of type {type(user)}")
    return user