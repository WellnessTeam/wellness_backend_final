from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class LogBase(BaseModel):
    req_url: str
    method: str
    req_param: Optional[str] = None
    res_param: Optional[str] = None
    msg: str
    code: int
    time_stamp: datetime

class LogCreate(LogBase):
    pass

class Log(LogBase):
    id: int

    class Config:
        orm_mode = True
