from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from jose import jwt
from schemas.user import UserCreate
from db import crud
from db.crud import calculate_age, get_user_by_email
from db.session import get_db
from db.models import Auth, User
import os
from dotenv import load_dotenv
from datetime import date, datetime, timedelta
import pytz  
from fastapi.responses import JSONResponse
from services.auth_service import create_access_token, create_refresh_token
from core.logging import logger
from core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from utils.format import KST,  format_datetime

router = APIRouter()

@router.post("/register")
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        # 이메일 중복 확인
        existing_user = await get_user_by_email(db, email=user.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered."
            )
            
        # 생년월일이 현재 연도와 같은지 확인
        current_year = datetime.now().year
        if user.birthday.year == current_year:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Birthday cannot be the current year."
            )

        # 성별 변환
        gender_value = 0 if user.gender == "남성" else 1 if user.gender == "여성" else None
        if gender_value is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid gender information."
            )

        # 생년월일로 나이를 계산
        user_age = calculate_age(user.birthday)
        
        # 사용자 생성
        new_user = await crud.create_user(db=db, user=user, age=user_age, gender=gender_value)

        # 권장 영양소 계산 및 저장
        recommendation = await crud.calculate_and_save_recommendation(db, new_user)
        if recommendation is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save recommendation")

        # total_today 생성
        today = date.today()
        total_today = await crud.create_total_today(db, new_user.id, today)
        if total_today is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create total_today")

        # JWT 토큰 생성
        access_token = create_access_token(
            data={"user_email": new_user.email},
            expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
        )
        refresh_token = create_refresh_token(
            data={"dummy": "dummy_value"}, 
            expires_delta=REFRESH_TOKEN_EXPIRE_DAYS
        )
        
        # KST 시간으로 변환하여 데이터베이스에 저장
        now_kst = datetime.now(KST)
        access_created_at = now_kst
        access_expired_at = now_kst + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_created_at = now_kst
        refresh_expired_at = now_kst + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        # 토큰 정보 저장
        new_user_auth_entry = Auth(
            user_id=new_user.id,
            access_token=access_token,
            access_created_at=access_created_at,
            access_expired_at=access_expired_at,
            refresh_token=refresh_token,
            refresh_created_at=refresh_created_at,
            refresh_expired_at=refresh_expired_at
        )
        
        # 모든 작업을 완료한 후에 커밋
        db.add(new_user_auth_entry)
        await db.commit()

        return {
            "status": "success",
            "status_code": 201,
            "detail": {
                "wellness_info": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "user_email": new_user.email,
                    "user_nickname": new_user.nickname.encode('utf-8').decode('utf-8'),
                    "user_birthday": new_user.birthday,
                    "user_age": user_age,
                    "user_gender": gender_value,
                    "user_height": new_user.height,
                    "user_weight": new_user.weight
                }
            },
            "message": "Registration is complete"
        }

    except (SQLAlchemyError, HTTPException) as e:
        await db.rollback()  # 오류 발생 시 롤백
        logger.error(f"Failed to create user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )
        
    except Exception as e:
        await db.rollback()  # 예상치 못한 오류에도 롤백 수행
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )

