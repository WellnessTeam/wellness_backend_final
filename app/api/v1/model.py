from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, status
import requests
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from services.auth_service import validate_token
from db.session import get_db
from db.models import Food_List, Recommend 
from utils.image_processing import extract_exif_data, determine_meal_type, format_date
from utils.s3 import upload_image_to_s3
import mimetypes
from io import BytesIO
import os
import uuid
import datetime
from fastapi.responses import JSONResponse
from decimal import Decimal
from core.logging import logger
from utils.format import decimal_to_float
from db import models

router = APIRouter()

# 허용된 이미지 파일 형식 (MIME 타입)
ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/jpg"]


@router.post("/predict")
async def classify_image(
    current_user: models.User = Depends(validate_token),
    file: UploadFile = File(...), 
    db: AsyncSession = Depends(get_db)
):
    try:
        file_bytes = await file.read()
        file_extension = file.filename.split(".")[-1]
        unique_file_name = f"{uuid.uuid4()}.{file_extension}"
        bucket_name = os.getenv("BUCKET_NAME", "default_bucket_name")
        
        # MIME 타입 확인
        mime_type, _ = mimetypes.guess_type(file.filename)
        if mime_type not in ALLOWED_MIME_TYPES:
            return JSONResponse(
                {
                    "status": "Forbidden",
                    "status_code": 403,
                    "detail": "Invalid file type. Allowed types: jpg, jpeg, png."
                },
                status_code=status.HTTP_403_FORBIDDEN
            )

        # 이미지 S3 업로드 처리
        try:
            image_url = upload_image_to_s3(BytesIO(file_bytes), bucket_name, unique_file_name)
        except Exception as e:
            return JSONResponse(
                {
                    "status": "Bad Request",
                    "status_code": 403,
                    "detail": f"Failed to upload image to s3: {str(e)}"
                },
                status_code=status.HTTP_403_FORBIDDEN
            )

        # EXIF 데이터에서 날짜 추출        
        date = extract_exif_data(file_bytes)
        if date:
            formatted_date = format_date(date)
        else:
            current_time = datetime.datetime.now()
            formatted_date = current_time.strftime("%Y-%m-%d %H:%M:%S")
            date = current_time  # datetime 객체를 date로 설정

        # meal_type 및 meal_type_id 설정
        meal_type = determine_meal_type(date) if date else "기타"
        logger.info(f"Determined meal_type: {meal_type}, from date: {date}")
        meal_type_id_map = {
            "아침": 0,
            "점심": 1,
            "저녁": 2,
            "기타": 3
        }
        meal_type_id = meal_type_id_map.get(meal_type, 3)

        # Model API 호출
        model_api_url = "http://127.0.0.1:8001/predict_url/"
        try:
            response = requests.post(model_api_url, params={"image_url": image_url})
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Model API request failed: {str(e)}")
            return JSONResponse(
                {
                    "status": "Internal Server Error",
                    "status_code": 500,
                    "detail": f"Model API request failed: {str(e)}"
                },
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 모델 응답에서 category_id 가져오기
        category_id = response.json().get("category_id")
        if category_id is None:
            return JSONResponse(
                {
                    "status": "Bad Request",
                    "status_code": 400,
                    "detail": "Category ID is required"
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # 음식 카테고리 가져오기 (비동기 쿼리)
        result = await db.execute(select(Food_List).where(Food_List.category_id == category_id))
        food = result.scalars().first()
        if not food:
            return JSONResponse(
                {
                    "status": "Not Found",
                    "status_code": 404,
                    "detail": "Food category not found"
                },
                status_code=status.HTTP_404_NOT_FOUND
            )

        # 사용자 권장 영양소 정보 가져오기 (비동기 쿼리)
        result = await db.execute(select(Recommend).where(Recommend.user_id == current_user.id))
        recommend = result.scalars().first()
        if not recommend:
            return JSONResponse(
                {
                    "status": "Not Found",
                    "status_code": 404,
                    "detail": "Recommendation not found"
                },
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # UTF-8 인코딩
        meal_type_utf8 = meal_type.encode('utf-8').decode('utf-8')
        category_name_utf8 = food.category_name.encode('utf-8').decode('utf-8')

        # 응답 반환
        return JSONResponse(
            {
                "status": "success",
                "status_code": 201,
                "detail": {
                    "wellness_image_info": {
                        "date": formatted_date,
                        "meal_type": meal_type_utf8,
                        "meal_type_id": meal_type_id,
                        "category_id": category_id,
                        "category_name": category_name_utf8,
                        "food_kcal": decimal_to_float(food.food_kcal),
                        "food_car": round(float(food.food_car)),
                        "food_prot": round(float(food.food_prot)),
                        "food_fat": round(float(food.food_fat)),
                        "rec_kcal": decimal_to_float(recommend.rec_kcal),
                        "rec_car": round(float(recommend.rec_car)),
                        "rec_prot": round(float(recommend.rec_prot)),
                        "rec_fat": round(float(recommend.rec_fat)),
                        "image_url": image_url
                    }
                },
                "message": "Image Classify Information saved successfully"
            },
            media_type="application/json; charset=utf-8"
        )

    except Exception as e:
        logger.error(f"Internal server error: {str(e)}")
        return JSONResponse(
            {
                "status": "Internal Server Error",
                "status_code": 500,
                "detail": f"Internal server error: {str(e)}"
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
