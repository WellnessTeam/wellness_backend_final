from pydantic import BaseModel, EmailStr, Field
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar, Optional
from sqlalchemy import TIMESTAMP, Column
from sqlalchemy.sql import func

class UserBase(BaseModel):
    gender: int
    height: Decimal
    weight: Decimal
    birthday: date
    email: EmailStr
    nickname: str = Field(max_length=20)

class UserCreate(UserBase):
    nickname: str = Field(max_length=20)
    email: EmailStr
    birthday: date
    gender: str
    height: Decimal
    weight: Decimal
    
class UserLogin(BaseModel):
    email: EmailStr
    nickname: str


class User(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True  

class UserUpdate(BaseModel):
    birthday: date
    gender: int
    height: Decimal
    weight: Decimal
    email: EmailStr
    nickname: str = Field(max_length=20)

class Recommendations(BaseModel):
    rec_kcal: Decimal
    rec_car: Decimal
    rec_prot: Decimal
    rec_fat: Decimal

class TotalToday(BaseModel):
    total_kcal: Decimal
    total_car: Decimal
    total_prot: Decimal
    total_fat: Decimal
    condition: bool


class WellnessInfo(BaseModel):
    user_birthday: date
    user_age: int
    user_gender: int
    user_nickname: str
    user_height: Decimal
    user_weight: Decimal
    user_email: EmailStr
    user_nickname: str = Field(max_length=20)
    

      
# 기존 UserResponsDetail에  recomendations, total_today 추가
class UserResponseDetail(BaseModel):
    wellness_info: WellnessInfo
    recommendations: Recommendations
    total_today: TotalToday

class UserResponse(BaseModel):
    status: str
    status_code: int
    detail: UserResponseDetail
    message: str

# 에러 응답 스키마
class ErrorResponse(BaseModel):
    status: str
    status_code: int
    message: str