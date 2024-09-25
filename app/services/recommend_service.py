# /app/services/recommend_service.py
from sqlalchemy.orm import Session
from db import crud, models
from fastapi import HTTPException
from decimal import Decimal, ROUND_HALF_UP


def recommend_nutrition(weight: Decimal, height: Decimal, age: int, gender: int):
    if weight <= 0 or height <= 0 or age <= 0 or gender not in [0, 1]:
        raise ValueError("Invalid input parameters")

    if gender == 0:  # 남성일 경우
        bmr = Decimal('88.362') + (Decimal('13.397') * weight) + (Decimal('4.799') * height) - (Decimal('5.677') * Decimal(str(age)))
    else:  # 여성이거나 다른 경우
        bmr = Decimal('447.593') + (Decimal('9.247') * weight) + (Decimal('3.098') * height) - (Decimal('4.330') * Decimal(str(age)))
    rec_kcal = bmr * Decimal('1.55')  # 보통 활동량

    # 탄, 단, 지 비율 설정 5:3:2
    rec_car = (rec_kcal * Decimal('0.5')) / Decimal('4')  # 1g 4kcal
    rec_prot = (rec_kcal * Decimal('0.3')) / Decimal('4')  # 1g 4kcal
    rec_fat = (rec_kcal * Decimal('0.2')) / Decimal('9')  # 1g 9kcal

    rec_kcal = rec_kcal.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    rec_car = rec_car.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    rec_prot = rec_prot.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    rec_fat = rec_fat.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    return {
        "rec_kcal": rec_kcal,
        "rec_car": rec_car,
        "rec_prot": rec_prot,
        "rec_fat": rec_fat
    }