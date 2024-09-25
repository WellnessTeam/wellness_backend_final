from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func  # 추가된 부분
from db.session import get_db
from db.models import History, User, Meal_Type, Food_List
from services.auth_service import validate_token
from datetime import datetime, date, timedelta
import logging
from core.logging import logger
from utils.format import decimal_to_float, datetime_to_string, KST


router = APIRouter()

@router.get("/meal_records")
async def get_meal_records(
    today: date = Query(None, description="The date for recommendation in YYYY-MM-DD format"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(validate_token)
):
    logger.info(f"Request received from user ID: {current_user.id}")

    # 오늘 날짜로 설정
    if today is None:
        today = datetime.now(KST).date().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"No date provided; usi ng today's date in KST: {today}")

    try:
        logger.info(f"Querying meals for date: {today}")

        # category_id에 해당하는 첫 번째 레코드의 영양소 값을 가져옴
        stmt = select(
            History.id.label("history_id"),
            History.date,
            History.meal_type_id,
            History.category_id,
            Meal_Type.type_name.label("meal_type_name"),
            Food_List.category_name.label("category_name"),
            func.first_value(Food_List.food_kcal).over(partition_by=History.category_id).label("food_kcal"),
            func.first_value(Food_List.food_car).over(partition_by=History.category_id).label("food_car"),
            func.first_value(Food_List.food_prot).over(partition_by=History.category_id).label("food_prot"),
            func.first_value(Food_List.food_fat).over(partition_by=History.category_id).label("food_fat")
        ).join(Food_List, History.category_id == Food_List.category_id) \
         .join(Meal_Type, History.meal_type_id == Meal_Type.id) \
         .filter(History.date >= today) \
         .filter(History.date < today + timedelta(days=1)) \
         .filter(History.user_id == current_user.id) \
         .order_by(History.id)


        result = await db.execute(stmt)
        meals = result.fetchall()

        logger.info(f"Number of meals retrieved: {len(meals)}")
        
        if not meals:
            return JSONResponse(
                content={
                    "status": "success",
                    "status_code": 200,
                    "detail": {
                        "Wellness_meal_list": []
                    },
                    "message": "No meals recorded today",
                },
                media_type="application/json; charset=utf-8"
            )

        # 응답 데이터 포맷팅
        meal_list = [{
            "history_id": meal.history_id,
            "meal_type_name": meal.meal_type_name,
            "category_name": meal.category_name,
            "food_kcal": decimal_to_float(meal.food_kcal),
            "food_car": round(decimal_to_float(meal.food_car)),
            "food_prot": round(decimal_to_float(meal.food_prot)),
            "food_fat": round(decimal_to_float(meal.food_fat)),
            "date": datetime_to_string(meal.date)
        } for meal in meals]

        logger.info(f"Retrieved today's meal records: {meal_list}")

        # 응답 반환
        return JSONResponse(
            content={
                "status": "success",
                "status_code": 200,
                "detail": {
                    "Wellness_meal_list": meal_list
                },
                "message": "Today's meal records retrieved successfully."
            },
            media_type="application/json; charset=utf-8"
        )

    except Exception as e:
        logger.error(f"Failed to retrieve meal records: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while retrieving meal records")

