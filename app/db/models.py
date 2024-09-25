from sqlalchemy import ForeignKey, Column, Integer, String, DECIMAL, TIMESTAMP, DATE, text, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from db.session import Base
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
import pytz

class Auth(Base):
    __tablename__ = 'auth'
    
    id= Column(Integer, primary_key=True,autoincrement=True)
    user_id= Column(Integer, ForeignKey('user_info.id'), nullable=False)
    access_token= Column(String(255), nullable=False, unique=True)
    access_created_at= Column(DateTime(timezone=True), nullable=False)
    access_expired_at= Column(DateTime(timezone=True), nullable=False)
    refresh_token= Column(String(255), nullable=False, unique=True)
    refresh_created_at= Column(DateTime(timezone=True), nullable=False)
    refresh_expired_at= Column(DateTime(timezone=True), nullable=False)
    
    user= relationship("User", back_populates="auth")

class User(Base): 
    __tablename__ = 'user_info'

    id = Column(Integer, primary_key=True, autoincrement=True)
    age = Column(Integer, nullable=False)
    gender = Column(Integer, nullable=False)
    height = Column(DECIMAL(4, 1), nullable=False)
    weight = Column(DECIMAL(4, 1), nullable=False)
    birthday = Column(DATE, nullable=False)
    email = Column(String(100), nullable=False)
    nickname = Column(String(20), nullable=False)
    created_at = Column(TIMESTAMP, default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, default=func.now(), onupdate=func.now(), nullable=False)
    
    # 관계 설정: Recommend 클래스와의 연결
    recommendations = relationship("Recommend", back_populates="user")
    total_today = relationship("Total_Today", back_populates="user")
    history = relationship("History", back_populates="user")
    auth = relationship("Auth", back_populates="user")


class Recommend(Base):
    __tablename__ = 'recommend'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user_info.id'), nullable=False)
    rec_kcal = Column(DECIMAL(6, 2), nullable=False)
    rec_car = Column(DECIMAL(6, 2), nullable=False)
    rec_prot = Column(DECIMAL(6, 2), nullable=False)
    rec_fat = Column(DECIMAL(6, 2), nullable=False)
    updated_at = Column(TIMESTAMP, default=func.now(), onupdate=func.now(), nullable=False)
    
    # User와 관계 설정
    user = relationship("User", back_populates="recommendations")


class Food_List(Base):
    __tablename__ = 'food_list'

    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, nullable=False)
    food_name = Column(String(15), nullable=False)
    category_name = Column(String(10), nullable=False)
    food_kcal = Column(DECIMAL(6, 2), nullable=False)
    food_car = Column(DECIMAL(6, 2), nullable=False)
    food_prot = Column(DECIMAL(6, 2), nullable=False)
    food_fat = Column(DECIMAL(6, 2), nullable=False)

    history = relationship("History", back_populates="food")


class Meal_Type(Base):
    __tablename__ = 'meal_type'

    id = Column(Integer, primary_key=True)
    type_name = Column(String(5), nullable=False)

    histories = relationship("History", back_populates="meal_type")


class History(Base):
    __tablename__ = 'history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('user_info.id'), nullable=False)
    category_id = Column(Integer, ForeignKey('food_list.id'), nullable=False)
    meal_type_id = Column(Integer, ForeignKey('meal_type.id'), nullable=False)
    image_url = Column(String(255), nullable=False)
    date = Column(TIMESTAMP, nullable=False)
    created_at = Column(TIMESTAMP, default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="history")
    food = relationship("Food_List", back_populates="history")
    meal_type = relationship("Meal_Type", back_populates="histories")


class Total_Today(Base):
    __tablename__ = 'total_today'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user_info.id'), nullable=False)
    total_kcal = Column(DECIMAL(6, 2), nullable=False)
    total_car = Column(DECIMAL(6, 2), nullable=False)
    total_prot = Column(DECIMAL(6, 2), nullable=False)
    total_fat = Column(DECIMAL(6, 2), nullable=False)
    condition = Column(Boolean, nullable=False)
    created_at = Column(TIMESTAMP, default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, default=func.now(), onupdate=func.now(), nullable=False)
    today = Column(DATE, nullable=False)
    history_ids = Column(ARRAY(Integer), nullable=False)

    user = relationship("User", back_populates="total_today")
    
class Log(Base):
    __tablename__ = 'logs'

    id = Column(Integer, primary_key=True, index=True)
    req_url = Column(String, nullable=False)          # 요청 URL
    method = Column(String, nullable=False)           # HTTP 메서드 (GET, POST 등)
    req_param = Column(Text, nullable=True)           # 요청 파라미터
    res_param = Column(Text, nullable=True)           # 응답 파라미터
    msg = Column(String, nullable=True)               # 추가 메시지 (예: 요청 완료, 오류 메시지)
    code = Column(Integer, nullable=False)            # 응답 코드 (예: 200, 404, 500 등)
    time_stamp = Column(DateTime, default=datetime.now(pytz.utc))  # 로그 생성 시간

    def __repr__(self):
        return f"<Log(id={self.id}, req_url={self.req_url}, method={self.method}, code={self.code})>"