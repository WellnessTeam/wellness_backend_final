from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1 import model
from services.auth_service import validate_token
from db import crud, models
from db.session import get_db
from decimal import Decimal
from datetime import datetime
from fastapi.responses import JSONResponse
import logging
from datetime import date
from core.logging import logger
from utils.format import decimal_to_float

router = APIRouter()

@router.get("/eaten_nutrient")
async def get_recommend_eaten(
    today: date = Query(None, description="The date for recommendation in YYYY-MM-DD format"),
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(validate_token)     
):
    # 만약 today 값이 전달되지 않았다면, 현재 서버 날짜로 설정
    if not today:
        today = datetime.now().strftime("%Y-%m-%d")
    
    # 로그 추가: current_user 확인
    logger.info(f"current_user: {current_user}, type: {type(current_user)}")
    
    # 문자열 date를 datetime 객체로 변환
    try:
        date_obj = datetime.strptime(today, "%Y-%m-%d").date()
    except ValueError:
        logger.error("Invalid date format. Please use YYYY-MM-DD.")
        raise HTTPException(status_code=400, detail="Invalid date format. Please use YYYY-MM-DD.")
    
    # 사용자 정보 확인
    if current_user is None:
        logger.error("User not found")
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # 권장 영양소 조회 (비동기 처리)
        recommendation = await crud.get_or_update_recommendation(db, current_user)
    except HTTPException as e:
        logger.error(f"Error retrieving recommendations: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    if recommendation is None:
        logger.error("Failed to retrieve or create recommendations")
        raise HTTPException(status_code=404, detail="Failed to retrieve or create recommendations")

    # 오늘의 총 섭취량 조회 또는 생성 (비동기 처리)
    try:
        total_today = await crud.get_total_today(db, current_user, date_obj)
    except HTTPException as e:
        logger.error(f"Error retrieving or creating total_today: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="Unexpected server error")
        
    if total_today is not None:
        total_today.condition = total_today.total_kcal > recommendation.rec_kcal
    else:
        raise HTTPException(status_code=404, detail="total_today not found")
    
    # total_today 업데이트 (비동기 처리)
    try:
        await crud.update_total_today(db, total_today)
    except Exception as e:
        logger.error(f"Failed to update total_today: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update total_today")

    return JSONResponse(
        content={
            "status": "success",
            "status_code": 200,
            "detail": {
                "wellness_recommend_info": {
                    "user_nickname": current_user.nickname,
                    "total_kcal": decimal_to_float(total_today.total_kcal),
                    "total_car": decimal_to_float(total_today.total_car),
                    "total_prot": decimal_to_float(total_today.total_prot),
                    "total_fat": decimal_to_float(total_today.total_fat),
                    "rec_kcal": decimal_to_float(recommendation.rec_kcal),
                    "rec_car": decimal_to_float(recommendation.rec_car),
                    "rec_prot": decimal_to_float(recommendation.rec_prot),
                    "rec_fat": decimal_to_float(recommendation.rec_fat),
                    "condition": total_today.condition
                }
            },
            "message": "Wellness user's total intake and recommended values have been successfully retrieved."
        },
        media_type="application/json; charset=utf-8"
    )
