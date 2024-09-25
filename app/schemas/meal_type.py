from pydantic import BaseModel

class MealTypeBase(BaseModel):
    type_name: str

class MealTypeCreate(MealTypeBase):
    pass

class MealTypeUpdate(MealTypeBase):
    pass

class MealTypeInDB(MealTypeBase):
    id: int

    class Config:
        orm_mode = True