from decimal import Decimal
from pydantic import BaseModel
from decimal import Decimal
from typing import ClassVar
from sqlalchemy import TIMESTAMP, Column
from sqlalchemy.sql import func
from datetime import datetime


class RecommendBase(BaseModel):
    rec_kcal: Decimal
    rec_car: Decimal
    rec_prot: Decimal
    rec_fat: Decimal

class RecommendCreate(RecommendBase):
    pass

class RecommendUpdate(RecommendBase):
    pass

class RecommendInDB(RecommendBase):
    id: int
    updated_at: datetime
    class Config:
        arbitrary_types_allowed = True
        from_attributes = True
