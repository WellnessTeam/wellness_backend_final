from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from jose import jwt, JWTError
from schemas.user import UserLogin
from db.session import get_db
from db.models import Auth, User
import os
from datetime import datetime, timedelta
from core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from core.logging import logger
from services.auth_service import create_access_token, create_refresh_token, is_access_token_expired, verify_refresh_token
from core.logging import logger
import pytz  
from pytz import UTC
from utils.format import KST, format_datetime

router = APIRouter()

@router.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    logger.info(f"Login attempt: {user.email}")

    # User lookup
    stmt = select(User).where(User.email == user.email)
    result = await db.execute(stmt)
    db_user = result.scalars().first()
    
    if not db_user:
        logger.error(f"User not found: {user.email}")
        raise HTTPException(status_code=400, detail="User not found")

    # Check auth table for user token
    stmt_auth = select(Auth).where(Auth.user_id == db_user.id)
    result_auth = await db.execute(stmt_auth)
    auth_entry = result_auth.scalars().first()

    if auth_entry:
        # Check if access token has expired
        if is_access_token_expired(auth_entry.access_expired_at):
            logger.info("Access token expired. Checking refresh token.")
            try:
                verify_refresh_token(auth_entry.refresh_token, auth_entry.refresh_expired_at)
                logger.info("Refresh token valid. Issuing new access token.")

                # Refresh token is valid, issue new access token
                access_token = create_access_token(
                    data={"user_email": db_user.email},
                    expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
                )
                auth_entry.access_token = access_token
                now_kst = datetime.now(KST)
                auth_entry.access_created_at = now_kst
                auth_entry.access_expired_at = now_kst + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

                await db.commit()
                return {
                    "status": "success",
                    "status_code": 200,
                    "detail": {
                        "wellness_info": {
                            "access_token": auth_entry.access_token,
                            "refresh_token": auth_entry.refresh_token,
                            "token_type": "bearer",
                            "user_email": db_user.email,
                            "user_nickname": db_user.nickname
                        }
                    },
                    "message": "Access token renewed."
                }

            except HTTPException as e:
                logger.info("Refresh token expired. Issuing new tokens.")
                # Both access and refresh tokens expired; issue new ones
                access_token = create_access_token(
                    data={"user_email": db_user.email},
                    expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
                )
                refresh_token = create_refresh_token(
                    data={"dummy_data": "dummy_value"},
                    expires_delta=REFRESH_TOKEN_EXPIRE_DAYS
                )

                auth_entry.access_token = access_token
                auth_entry.refresh_token = refresh_token
                now_kst = datetime.now(KST)
                auth_entry.access_created_at = now_kst
                auth_entry.access_expired_at = now_kst + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                auth_entry.refresh_created_at = now_kst
                auth_entry.refresh_expired_at = now_kst + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

                await db.commit()
                logger.info(f"Updated auth entry for user_id {db_user.id}")
                return {
                    "status": "success",
                    "status_code": 201,
                    "detail": {
                        "wellness_info": {
                            "access_token": auth_entry.access_token,
                            "refresh_token": auth_entry.refresh_token,
                            "token_type": "bearer",
                            "user_email": db_user.email,
                            "user_nickname": db_user.nickname
                        }
                    },
                    "message": "New access and refresh tokens issued."
                }

        else:
            # Access token is still valid
            logger.info(f"Valid access token found for user_id: {db_user.id}")
            return {
                "status": "success",
                "status_code": 200,
                "detail": {
                    "wellness_info": {
                        "access_token": auth_entry.access_token,
                        "refresh_token": auth_entry.refresh_token,
                        "token_type": "bearer",
                        "user_email": db_user.email,
                        "user_nickname": db_user.nickname
                    }
                },
                "message": "Existing token provided."
            }
