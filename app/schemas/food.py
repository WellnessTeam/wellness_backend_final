from decimal import Decimal
from pydantic import BaseModel

class FoodListBase(BaseModel):
    category_id: int
    food_name: str
    category_name: str
    food_kcal: Decimal
    food_car: Decimal
    food_prot: Decimal
    food_fat: Decimal

class FoodListCreate(FoodListBase):
    pass

class FoodListUpdate(FoodListBase):
    pass

class FoodListInDB(FoodListBase):
    id: int

    class Config:
        orm_mode = True