from pydantic import BaseModel
from typing import List
from datetime import datetime, date

class TotalTodayBase(BaseModel):
    total_kcal: float
    total_car: float
    total_prot: float
    total_fat: float
    condition: bool
    today: date
    history_ids: List[int]

class TotalTodayCreate(TotalTodayBase):
    pass

class TotalTodayUpdate(TotalTodayBase):
    pass

class TotalTodayInDB(TotalTodayBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True