from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, DataError
from services import recommend_service
from api.v1 import recommend
from services.auth_service import validate_token
from db.models import Food_List, Recommend, Total_Today, History, Meal_Type, User, Auth, Log
from sqlalchemy import func
from decimal import Decimal
from datetime import date, datetime
from schemas.user import UserCreate
import schemas
from core.logging import logger
from schemas.log import LogCreate
import json

# 공통 예외 처리 헬퍼 함수
async def execute_db_operation(db: AsyncSession, operation):
    try:
        result = await operation()
        await db.commit()
        return result
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database operation failed: {str(e)}")
    
    # 민감한 정보 마스킹 함수
def mask_token(token: str) -> str:
    return token[:10] + '*' * (len(token) - 10) if token else token

def mask_email(email: str) -> str:
    parts = email.split('@')
    return f"{parts[0][:3]}{'*' * (len(parts[0]) - 3)}@{parts[1]}" if email else email

def mask_nickname(nickname: str) -> str:
    return nickname[:1] + '*' * (len(nickname) - 1) if nickname else nickname

# 로그 생성 함수
async def create_log(db: AsyncSession, log: LogCreate):
    try:
        # JSON 데이터를 파싱
        res_param = json.loads(log.res_param)
        
        # 민감한 정보 마스킹
        if 'detail' in res_param and 'wellness_info' in res_param['detail']:
            wellness_info = res_param['detail']['wellness_info']
            wellness_info['access_token'] = mask_token(wellness_info.get('access_token'))
            wellness_info['refresh_token'] = mask_token(wellness_info.get('refresh_token'))
            wellness_info['user_email'] = mask_email(wellness_info.get('user_email'))
            wellness_info['user_nickname'] = mask_nickname(wellness_info.get('user_nickname'))
        
        # 마스킹된 데이터를 다시 JSON 문자열로 변환
        masked_res_param = json.dumps(res_param)
    except json.JSONDecodeError:
        # JSON 파싱에 실패한 경우, 원본 데이터를 그대로 사용
        masked_res_param = log.res_param
    except Exception as e:
        logger.error(f"Error during log masking: {str(e)}")
        masked_res_param = log.res_param
        
    naive_time_stamp = log.time_stamp.replace(tzinfo=None)


    db_log = Log(
        req_url=log.req_url,
        method=log.method,
        req_param=log.req_param,
        res_param=masked_res_param,  # 마스킹된 데이터 사용
        msg=log.msg,
        code=log.code,
        time_stamp=naive_time_stamp
    )
    db.add(db_log)
    await db.commit()
    await db.refresh(db_log)
    return db_log

# 로그 조회 함수
async def get_daily_logs(session: AsyncSession, timestamp: datetime):
    # 여기서는 timestamp를 UTC 형식으로 그대로 사용
    statement = select(Log).where(Log.time_stamp >= timestamp)
    result = await session.execute(statement)
    return result.scalars().all()

# 오래된 로그 삭제 함수
async def delete_old_logs(session: AsyncSession, days: int):
    cutoff_time = datetime.now(pytz.utc) - timedelta(days=days)
    statement = delete(Log).where(Log.time_stamp < cutoff_time)
    await session.execute(statement)

# 사용자의 마지막 업데이트 기록 조회
async def get_user_updated_at(db: AsyncSession, current_user: User):
    try:
        stmt = select(User).where(User.id == current_user.id)
        result = await db.execute(stmt)
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.updated_at
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 사용자 ID로 권장 영양소 조회
async def get_recommend_by_user_id(db: AsyncSession, user_id: int):
    try:
        stmt = select(Recommend).where(Recommend.user_id == user_id)
        result = await db.execute(stmt)
        return result.scalars().first()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 권장 영양소 계산 및 저장(register api에 사용)
async def calculate_and_save_recommendation(db: AsyncSession, user: User):
    recommendation_result = recommend_service.recommend_nutrition(user.weight, user.height, user.age, user.gender)
    recommendation = Recommend(
        user_id=user.id,
        rec_kcal=recommendation_result["rec_kcal"],
        rec_car=recommendation_result["rec_car"],
        rec_prot=recommendation_result["rec_prot"],
        rec_fat=recommendation_result["rec_fat"]
    )
    db.add(recommendation)
    await db.commit()
    return recommendation

# 사용자 권장 영양소를 조회하거나 업데이트(recommend_eaten api에 사용)
async def get_or_update_recommendation(db: AsyncSession, current_user: User):
    try:
        stmt = select(Recommend).where(Recommend.user_id == current_user.id)
        result = await db.execute(stmt)
        recommendation = result.scalars().first()

        if not recommendation or recommendation.updated_at < current_user.updated_at:
            new_values = recommend_service.recommend_nutrition(
                current_user.weight, current_user.height, current_user.age, current_user.gender
            )
            
            if not recommendation:
                recommendation = Recommend(user_id=current_user.id)
                db.add(recommendation)

            recommendation.rec_kcal = new_values["rec_kcal"]
            recommendation.rec_car = new_values["rec_car"]
            recommendation.rec_prot = new_values["rec_prot"]
            recommendation.rec_fat = new_values["rec_fat"]
            recommendation.updated_at = func.now()

            await db.commit()
            await db.refresh(recommendation)

        return recommendation
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid data: Integrity constraint violated")
    except DataError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid data: Data type mismatch")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 총 섭취량 조회
async def get_total_today(db: AsyncSession, current_user: User, date_obj: date):
    try:
        logger.info(f"Checking total_today for user: {current_user.id} on date: {date_obj}")
        stmt = select(Total_Today).filter_by(user_id=current_user.id, today=date_obj)
        result = await db.execute(stmt)
        return result.scalars().first()
    except SQLAlchemyError as e:
        logger.error(f"SQLAlchemyError occurred while fetching total_today: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 총 섭취량 생성
async def create_total_today(db: AsyncSession, user_id: int, date_obj: date):
    try:
        logger.info(f"Creating total_today for user: {user_id} on date: {date_obj}")

        total_today = Total_Today(
            user_id=user_id,
            total_kcal=Decimal('0'),
            total_car=Decimal('0'),
            total_prot=Decimal('0'),
            total_fat=Decimal('0'),
            condition=False,
            created_at=func.now(),
            updated_at=func.now(),
            today=date_obj,
            history_ids=[]
        )
        db.add(total_today)
        await db.commit()
        await db.refresh(total_today)
        return total_today
    except IntegrityError:
        await db.rollback()
        logger.error("IntegrityError occurred while creating total_today")
        raise HTTPException(status_code=400, detail="Invalid data: Integrity constraint violated")
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"SQLAlchemyError occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Total_Today 업데이트
async def update_total_today(db: AsyncSession, total_today: Total_Today):
    try:
        max_value = Decimal('9999.99')
        total_today.total_kcal = min(total_today.total_kcal, max_value)
        total_today.total_car = min(total_today.total_car, max_value)
        total_today.total_prot = min(total_today.total_prot, max_value)
        total_today.total_fat = min(total_today.total_fat, max_value)

        if total_today.condition is None:
            total_today.condition = False

        await db.commit()
        await db.refresh(total_today)
        return total_today
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update Total_Today: {str(e)}")

# 음식 카테고리 조회
async def get_food_by_category(db: AsyncSession, category_id: int) -> Food_List:
    stmt = select(Food_List).where(Food_List.category_id == category_id)
    food_item = await db.execute(stmt)
    food_item = food_item.scalars().first()

    if not food_item:
        raise HTTPException(status_code=404, detail="Food category not found")

    return food_item

# 추천 영양소 조회
async def get_recommend_by_user_id(db: AsyncSession, user_id: int):
    try:
        stmt = select(Recommend).where(Recommend.user_id == user_id)
        result = await db.execute(stmt)
        return result.scalars().first()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 히스토리 생성
async def create_history(db: AsyncSession, current_user: User, category_id: int, meal_type_id: int, image_url: str, date: date):
    if not hasattr(current_user, 'id'):
        logger.error(f"current_user가 User 객체가 아님: {current_user}")
        raise HTTPException(status_code=400, detail="Invalid user object")

    new_history = History(
        user_id=current_user.id,
        category_id=category_id,
        meal_type_id=meal_type_id,
        image_url=image_url,
        date=date
    )
    db.add(new_history)
    await db.commit()
    await db.refresh(new_history)
    logger.info(f"new_history 저장됨: {new_history}")
    return new_history

# meals 조회 함수 (ORM 사용)
async def get_meals_by_user_and_date(db: AsyncSession, current_user: User, today: date):
    logger.info(f"get_meals_by_user_and_date 호출됨, user_id: {current_user.id}, date: {today}")
    
    # 쿼리 작성: History.date의 날짜 부분만 비교
    stmt = (
        select(
            History.id.label("history_id"),
            Meal_Type.type_name.label("meal_type_name"),
            Food_List.category_name,
            Food_List.food_kcal,
            Food_List.food_car,
            Food_List.food_prot,
            Food_List.food_fat,
            History.date
        )
        .join(Food_List, History.category_id == Food_List.category_id)
        .join(Meal_Type, History.meal_type_id == Meal_Type.id)
        .filter(func.date(History.date) == today)  # 날짜 비교
        .filter(History.user_id == current_user.id)
    )
    
    logger.info(f"Executing query: {stmt}")
    meals = await db.execute(stmt)
    return meals.scalars().all()

# 사용자 조회
async def get_user_by_email(db: AsyncSession, email: str):
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    return result.scalars().first()

# 사용자 생성
async def create_user(db: AsyncSession, user: UserCreate, age: int, gender: int):
    db_user = User(
        birthday=user.birthday,
        age=age,
        gender=gender,
        nickname=user.nickname,
        height=user.height,
        weight=user.weight,
        email=user.email
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def update_total_today_condition(db: AsyncSession, total_today_id: int, new_condition: bool):
    try:
        # 비동기적으로 total_today 레코드 가져오기
        stmt = select(Total_Today).where(Total_Today.id == total_today_id)
        total_today_result = await db.execute(stmt)
        total_today = total_today_result.scalars().first()
        
        if total_today:
            stmt = select(Recommend).where(Recommend.user_id == total_today.user_id)
            recommendation_result = await db.execute(stmt)
            recommendation = recommendation_result.scalars().first()

            if recommendation:
                # 새로운 condition을 계산하고 업데이트
                new_condition = total_today.total_kcal > recommendation.rec_kcal

                # condition이 변경되었을 때만 업데이트
                if total_today.condition != new_condition:
                    total_today.condition = new_condition
                    await db.commit()
                    await db.refresh(total_today)

        return total_today

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error occurred: {e}")
        return None

    except Exception as e:
        await db.rollback()
        logger.error(f"An unexpected error occurred: {e}")
        return None

# 만 나이 계산 함수 (동기 처리 가능)
def calculate_age(birth_date) -> int:
    today = date.today()
    age = today.year - birth_date.year

    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1
    
    return age
