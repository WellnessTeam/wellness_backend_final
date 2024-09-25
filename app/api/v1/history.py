from decimal import Decimal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select  # select() 사용
from sqlalchemy.exc import SQLAlchemyError
from db.session import get_db
from db.models import History, Food_List, Meal_Type, User
from schemas.history import HistoryCreateRequest
from services.auth_service import validate_token
from core.logging import logger
from datetime import datetime
from utils.format import decimal_to_float, datetime_to_string, fix_date_format

router = APIRouter()


@router.post("/save_and_get")
async def save_to_history_and_get_today_history(
    history_data: HistoryCreateRequest,  
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(validate_token)
):
    # current_user가 올바르게 전달되었는지 확인
    if not hasattr(current_user, 'id'):
        raise HTTPException(status_code=400, detail="Invalid user object")
    
    try:
        # 날짜 형식 수정
        fixed_date = fix_date_format(history_data.date)
        history_data.date = fixed_date  # 수정된 날짜를 다시 할당
    
        # 요청 받은 사용자 정보 로그 출력
        logger.info(f"current_user 확인: {current_user}, id: {current_user.id}")
        
        # 받은 요청 데이터 확인
        logger.debug(f"Received history data: {history_data}")
        
        # 새 기록을 데이터베이스에 저장
        new_history = History(
            user_id=current_user.id,
            category_id=history_data.category_id,
            meal_type_id=history_data.meal_type_id,
            image_url=history_data.image_url,
            date=history_data.date
        )
        db.add(new_history)
        await db.commit()
        await db.refresh(new_history)
        logger.info(f"New history saved: {new_history}")

        # 기록과 음식 정보 조회 (오늘 날짜에 해당하는 모든 기록)
        stmt = select(
            History.id.label("history_id"),
            Meal_Type.type_name.label("meal_type_name"),
            Food_List.category_name,
            Food_List.food_kcal,
            Food_List.food_car,
            Food_List.food_prot,
            Food_List.food_fat,
            History.date
        ).join(Food_List, History.category_id == Food_List.category_id) \
         .join(Meal_Type, History.meal_type_id == Meal_Type.id) \
         .filter(History.date == history_data.date) \
         .filter(History.user_id == current_user.id)

        result = await db.execute(stmt)
        meals = result.fetchall()

        # 기록된 식사 내역이 10개 이상이면 에러 반환
        logger.info(f"Number of meals: {len(meals)}")
        if len(meals) >= 10:
            return JSONResponse(
                {
                    "status": "Too Many Requests",
                    "status_code": 429,
                    "detail": "There are too many meal records for today."
                },
                status_code=429
            )

        # 응답 데이터 포맷팅
        meal_list = [
            {
                "history_id": meal.history_id,
                "meal_type_name": meal.meal_type_name,
                "category_name": meal.category_name,
                "food_kcal": decimal_to_float(meal.food_kcal),
                "food_car": round(decimal_to_float(meal.food_car)),
                "food_prot": round(decimal_to_float(meal.food_prot)),
                "food_fat": round(decimal_to_float(meal.food_fat)),
                "date": datetime_to_string(meal.date)   
            }
            for meal in meals
        ]
        logger.info(f"Formatted meal list for response: {meal_list}")

        # 응답 반환
        return JSONResponse(
            content={
                "status": "success",
                "status_code": 201,
                "detail": {
                    "Wellness_meal_list": meal_list
                },
                "message": "meal_list information saved successfully"
            },
            media_type="application/json; charset=utf-8"
        )
        
    except SQLAlchemyError as e:
        # 저장 실패 시 에러 처리
        logger.error(f"Failed to save history: {e}")
        return JSONResponse(
            {
                "status": "Internal Server Error",
                "status_code": 500,
                "detail": "An error occurred while saving the information. The information was not saved."
            },
            status_code=500
        )
